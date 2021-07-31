/*
 * Copyright (C) 2020 Noel Kuntze for Contauro AG
 * Copyright (C) 1991-2018 Free Software Foundation, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "vici_prompt.h"
#include "vici_builder.h"

#include <threading/mutex.h>
#include <threading/condvar.h>
#include <credentials/sets/mem_cred.h>
#include <credentials/sets/callback_cred.h>

#include <library.h>
#include <daemon.h>

#include <ctype.h>
#include <errno.h>

#define PROMPT_TIMEOUT_MS 15000

typedef struct private_vici_prompt_t private_vici_prompt_t;

typedef struct private_notify_prompt_job_t private_notify_prompt_job_t;

/**
 * Directory for saved X.509 CRLs
 */
#define CRL_DIR SWANCTLDIR "/x509crl"

/**
 * Private data of an vici_prompt_t object.
 */
struct private_vici_prompt_t {

	/**
	 * Public vici_prompt_t interface.
	 */
	vici_prompt_t public;

	/**
	 * Dispatcher
	 */
	vici_dispatcher_t *dispatcher;

	/**
	 * Lock for data
	 */
	mutex_t *lock;

	/**
	 * Reused in-memory credential set
	 */
	mem_cred_t *creds;

	/**
	 * Callback credential set to get secrets
	 */
	callback_cred_t *cb;

	/**
	 * list containing registered VICI clients for prompting for credentials
	 */

	linked_list_t *prompt_clients;

	/**
	 * Condvar for signaling received credentials
	 */
	condvar_t *cond;

	/**
	 * Part of the cond
	 */
	mutex_t *mutex;

	/**
	 * Timeout for waiting for a reply to the prompt
	 */
	u_int timeout;

	/**
	 * prompt requests in progress
	 */

	linked_list_t *requests_in_progress;
	
	/**
	 * Stores whether this is enabled. Can be enabled by just connecting a client.
	 * Can be disabled again by sending the prompt-disable command
	 */
	bool enabled;
};

typedef struct {
	uint32_t id;
} prompt_client_t;

typedef struct {
	uint32_t id;
	shared_key_t *shared_key;
	shared_key_type_t type;
} prompt_client_reply_t;

typedef struct {
	identification_t *me;
	identification_t *other;
	shared_key_type_t type;
	/* stores objects of type prompt_client_reply_t */
	linked_list_t *clients;
	char *msg;
	mutex_t *mutex;
	size_t refcnt;
} prompt_request_in_progress_t;

typedef struct {
	job_t job_interface;
} notify_prompt_job_t;

struct private_notify_prompt_job_t {
	notify_prompt_job_t public;
	private_vici_prompt_t *prompt;	
	identification_t *me;
	identification_t *other;
	char *msg;
	shared_key_type_t type;
	bool timeout;
};

/* Ahead declaration */
notify_prompt_job_t *notify_prompt_job_create(private_vici_prompt_t *prompt, 
	identification_t *me, identification_t *other, shared_key_type_t type,
	char *msg, bool timeout);

void sanitize_string(chunk_t message)
{
	chunk_t new = chunk_alloca(message.len);
	int i = 0, j = 0;
	for (;i<new.len;i++)
	{
		if ((isspace(message.ptr[i]) || isgraph(message.ptr[i])) &&
			message.ptr[i] != ':')
		{
			new.ptr[j++] = message.ptr[i];
		}
	}
	new.ptr[j++] = '\0';
	new.len = j;
	memcpy(message.ptr, new.ptr, j);
	message.len=j;
}

/* Subtract the `struct timeval' values X and Y,
	storing the result in RESULT.
	Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract (struct timeval *result, struct timeval *x, struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating @var{y}. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}


static void manage_command(private_vici_prompt_t *this,
							char *name, vici_command_cb_t cb, bool reg,
							vici_register_cb_t register_cb, void *user)
{
	this->dispatcher->manage_command(this->dispatcher, name,
									 reg ? cb : NULL, this, register_cb, user);
	DBG1(DBG_LIB, "register_cb: %p", register_cb);
}

bool compare_and_free_prompt_client_t_and_u_int(void *a, void *b)
{
	u_int da = *((u_int *) b);
	prompt_client_t *db = a;
	if (db->id == da)
	{
		free(db);
		return TRUE;
	}
	return FALSE;
}

void free_prompt_client_reply_t(void *a)
{
	prompt_client_reply_t *da = a;
	DESTROY_IF(da->shared_key);
	free(da);
}


CALLBACK(find_matching_prompt_request, bool, void *a, va_list args)
{
	prompt_request_in_progress_t *da = a, *db;
	VA_ARGS_VGET(args, db);
	return da->me->equals(da->me, db->me) && da->other->equals(da->other, db->other)
		&& da->type == db->type;    
}

CALLBACK(find_matching_client_and_id, bool, void *a, void *b)
{
	prompt_client_t *da = a;
	u_int id = * (u_int *)b;

	return da->id == id;
}

/**
 * Create a (error) reply message
 */
static vici_message_t* create_reply(bool error, char *fmt, ...)
{
	vici_builder_t *builder;
	va_list args;

	builder = vici_builder_create();
	builder->add_kv(builder, "success", error ? "no" : "yes");
	if (fmt)
	{
		va_start(args, fmt);
		builder->vadd_kv(builder, "errmsg", fmt, args);
		va_end(args);
	}
	return builder->finalize(builder);
}

void register_cb (void *user, char *name, u_int id, bool reg)
{
	private_vici_prompt_t *this = user;
	prompt_client_t *client;
	INIT (client,
			.id = id
	);
	
	this->lock->lock(this->lock);
	DBG3(DBG_LIB, "prompt client register cb");
	if (reg)
	{
		this->prompt_clients->insert_last(this->prompt_clients, client);
		this->enabled = true;
	} else {
		this->prompt_clients->remove(this->prompt_clients, &id,
			compare_and_free_prompt_client_t_and_u_int);
	}	
	this->lock->unlock(this->lock);
}
CALLBACK(prompt_disable, vici_message_t*,
	private_vici_prompt_t *this, char *name, u_int id, vici_message_t *message)
{
	this->lock->lock(this->lock);
	this->enabled = FALSE;	
	this->lock->unlock(this->lock);	
	DBG2(DBG_LIB, "vici client %d: prompt disabled", id);
	return create_reply(FALSE, "prompt disabled");
}

CALLBACK(prompt_reply, vici_message_t*,
	private_vici_prompt_t *this, char *name, u_int id, vici_message_t *message)
{
	prompt_request_in_progress_t *proc = NULL, *test = NULL;
	prompt_client_reply_t *reply = NULL;
	vici_message_t *msg = NULL;
	chunk_t def = { .ptr = NULL, .len = 0},
		key = message->get_value(message, def, "secret"), clone;

	char *remote_identity = message->get_str(message, NULL, "remote-identity"),
		 *local_identity = message->get_str(message, NULL, "local-identity");
	char *shared_secret_type = message->get_str(message, NULL, "secret-type");
	shared_key_type_t type;
	
	identification_t *me = identification_create_from_string(local_identity),
		*other = identification_create_from_string(remote_identity);
	
	if (!me || !other)
	{
		DBG1(DBG_LIB, "provided identities could not be parsed into "
			 "identification_t objects. Proceeding without using those as "
			 "matches.");
	}

	if (key.len == 0 || key.ptr == NULL)
	{
		return create_reply(FALSE, "no secret key found");
	}

	if (streq(shared_secret_type, "password"))
	{
		type = SHARED_EAP;
	} else if (streq(shared_secret_type, "pin"))
	{
		type = SHARED_PIN;
	} else {
		DBG1(DBG_LIB, "vici client %u: Provided secret type (%s) isn't "
			 "password or pin.", id, shared_secret_type);
		msg = create_reply(FALSE, "Provided secret type (%s) isn't "
							"password or pin.", shared_secret_type);
		goto out;
	}

	INIT(test,
		.me = me,
		.other = other,
		.type = type,
	);

	this->lock->lock(this->lock);
	
	if (!this->requests_in_progress->find_first(this->requests_in_progress,
												 find_matching_prompt_request,
												 (void **) &proc, test))
	{
		DBG1(DBG_LIB, "vici client %u No matching prompt request found for vici client", id);
		msg = create_reply(FALSE, "No matching prompt request found for vici client", id);
		this->lock->unlock(this->lock);
		goto out;
	}

	clone = chunk_clone(key);

	INIT(reply,
		.id = id,
		.shared_key = shared_key_create(proc->type, clone),
		.type = type
	);

	proc->clients->insert_last(proc->clients, reply);

	msg = create_reply(FALSE, "reply stored");

	DBG1(DBG_LIB, "reply stored");
	this->lock->unlock(this->lock);
	this->mutex->lock(this->mutex);
	this->cond->broadcast(this->cond);
	this->mutex->unlock(this->mutex);


out:;
	if (test)
	{
		free(test);
	}

	me->destroy(me);
	other->destroy(other);
	return msg;
}
/**
 * Prompt a registered client for data
 * @param data	user supplied data
 * @param type	type of the requested shared key
 * @param me	own identity
 * @param other	peer identity
 * @return 		shared key
 */
CALLBACK(callback_shared, shared_key_t*,
	private_vici_prompt_t *this, shared_key_type_t type, identification_t *me,
	identification_t *other, const char *msg, id_match_t *match_me,
	id_match_t *match_other)
{
	bool ret = FALSE;
	enumerator_t *enumerator;
	prompt_client_reply_t *reply;
	prompt_request_in_progress_t *in_progress;
	shared_key_t *result = NULL;
	timeval_t now, then, timeout;

	chunk_t prompt = {
		.ptr = NULL,
		.len = 0,
	};

	DBG3(DBG_LIB, "received callback for secret_type %N", shared_key_type_names, type);

	/* Only prompt for user secrets, no PSKs or PPKs */
	if ((type != SHARED_EAP && type != SHARED_PIN) || !this->prompt_clients->get_count(this->prompt_clients) || !this->enabled)
	{
		return NULL;
	}

	if (msg) {
		/* prompt = chunk_alloc(strlen(msg)+1); */
		prompt.ptr = strndup(msg, strlen(msg)+1);
		prompt.len = strlen(msg)+1;
		sanitize_string(prompt);
	}

	time_monotonic(&then);
	timeval_add_ms(&then, this->timeout);

	if (prompt.ptr)
	{
		free(prompt.ptr);
	}

	INIT(in_progress,
		.clients = linked_list_create(),
		.me = me->clone(me),
		.other = other->clone(other),
		.type = type,
		.msg = strdupnull(prompt.ptr),
	);

	this->lock->lock(this->lock);
	this->requests_in_progress->insert_last(this->requests_in_progress, in_progress);

	lib->scheduler->schedule_job(lib->scheduler, (job_t*)notify_prompt_job_create(this,
		me->clone(me), other->clone(other), type, strdupnull(prompt.ptr), FALSE), 0);

	this->lock->unlock(this->lock);
	DBG3(DBG_LIB, "test");

	/* Wait for some signal that credentials were received or a timeout was reached. Condvar and timed job(?) */    
	while(true) {
		
		time_monotonic(&now);
		timeval_subtract(&timeout, &then, &now);
		uint64_t timeout_uint64 = timeout.tv_sec*1000*1000 + timeout.tv_usec;
		/* Handle wrap around */
		if ( timeout_uint64 < 0 || timeout_uint64 > this->timeout*1000*1000 ) {
			break;
		}

		DBG4(DBG_LIB, "remaining timeout: %lu.%06lu", timeout.tv_sec, timeout.tv_usec);

		this->mutex->lock(this->mutex);
		ret = this->cond->timed_wait_abs(this->cond, this->mutex, timeout);
		this->mutex->unlock(this->mutex);

		this->lock->lock(this->lock);
		enumerator = in_progress->clients->create_enumerator(in_progress->clients);
		while(enumerator->enumerate(enumerator, &reply))
		{
			if (reply->shared_key && reply->type == type)
			{
				DBG2(DBG_LIB, "found reply from vici client %u", reply->id);
				result = reply->shared_key->get_ref(reply->shared_key);
				/* Only cache passwords, not PINs because those can be time dependent (e.g. TOTP).
					If the PIN is wrong, then authentication will fail and that will then need to
					be retried via some to be implemented mechanism (if it's a reauthentication) */
				*match_me = ID_MATCH_PERFECT;
				*match_other = ID_MATCH_PERFECT;
				switch (type)
				{
					case SHARED_EAP:
						this->creds->add_shared(this->creds, reply->shared_key, me->clone(me), NULL);
						break;
					case SHARED_IKE:
						this->creds->add_shared(this->creds, reply->shared_key, me->clone(me), other->clone(other), NULL);
						break;
					default:
						break;
				}
				DBG2(DBG_LIB, "reply cached");
				ret = TRUE;
				break;
			}
		}

		enumerator->destroy(enumerator);
		enumerator = NULL;
		this->lock->unlock(this->lock);

		if (result)
		{
			break;
		}

		DBG4(DBG_LIB, "was woken up but did not find a valid reply for prompt request");
	}

	if (!ret) {
		DBG1(DBG_LIB, "timed out while waiting for credentials for %Y %Y", me, other);

		lib->scheduler->schedule_job(lib->scheduler, (job_t*) notify_prompt_job_create(this,
			me->clone(me), other->clone(other), type, strdupnull(prompt.ptr), TRUE), 0);
	}

	/* Timeout reached, now destroy all data structures to clean up */
	this->lock->lock(this->lock);
	this->requests_in_progress->remove(this->requests_in_progress, in_progress, NULL);
	this->lock->unlock(this->lock);
	in_progress->clients->destroy_function(in_progress->clients, free);
	in_progress->me->destroy(in_progress->me);
	in_progress->other->destroy(in_progress->other);
	if (in_progress->msg)
	{
		free(in_progress->msg);
	}
	free(in_progress);
	return result;
}

vici_message_t* prompt_request(void *user, char *name, u_int id, vici_message_t *request)
{
	return create_reply(FALSE, "");
}

void manage_commands(private_vici_prompt_t *this, bool reg)
{
	this->dispatcher->manage_event(this->dispatcher, "prompt-request", reg);
	this->dispatcher->manage_event(this->dispatcher, "prompt-reply", reg);
	this->dispatcher->manage_event(this->dispatcher, "prompt-disable", reg);
	manage_command(this, "prompt-request", prompt_request, reg, register_cb, this);    
	manage_command(this, "prompt-reply", prompt_reply, reg, register_cb, this);        
	manage_command(this, "prompt-disable", prompt_disable, reg, NULL, NULL);
}

METHOD(vici_prompt_t, destroy, void,
	private_vici_prompt_t *this)
{
	/** TODO: Rework */
	manage_commands(this, FALSE);
	this->requests_in_progress->destroy_function(this->requests_in_progress, free);
	this->prompt_clients->destroy_function(this->prompt_clients, free);
	lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
	lib->credmgr->remove_set(lib->credmgr, &this->cb->set);
	this->creds->destroy(this->creds);
	this->cb->destroy(this->cb);	
	free(this);
}

METHOD(job_t, notify_job_destroy, void,
	private_notify_prompt_job_t *this)
{
	this->me->destroy(this->me);
	this->other->destroy(this->other);
	free(this->msg);
	free(this);
}

METHOD(job_t, notify_job_get_priority, job_priority_t,
	private_notify_prompt_job_t *this)
{
	return JOB_PRIO_MEDIUM;
}

METHOD(job_t, notify_job_execute, job_requeue_t,
	private_notify_prompt_job_t *this)
{
	vici_builder_t *builder;
	vici_message_t *message;

	builder = vici_builder_create();
	builder->add_kv(builder, "remote-identity", "%Y", this->other);
	builder->add_kv(builder, "local-identity", "%Y", this->me);
	builder->add_kv(builder, "secret-type", this->type == SHARED_EAP ? "password" : "PIN");
	builder->add_kv(builder, "peer-message", "%s", this->msg);
	message = builder->finalize(builder);

	this->prompt->dispatcher->raise_event(this->prompt->dispatcher, this->timeout ? "prompt-timeout" : "prompt-request", 0, message);
	return JOB_REQUEUE_TYPE_NONE;
}

/**
 * See header
 */
notify_prompt_job_t *notify_prompt_job_create(private_vici_prompt_t *prompt, 
	identification_t *me, identification_t *other, shared_key_type_t type,
	char *msg, bool timeout)
{
	private_notify_prompt_job_t *this;

	INIT(this,
		.public = {
			.job_interface = {
				.execute = _notify_job_execute,
				.get_priority = _notify_job_get_priority,
				.destroy = _notify_job_destroy,
			},
		},
		.prompt = prompt,
		.me = me,
		.other = other,
		.type = type,
		.msg = msg,
		.timeout = timeout,
	);

	return &this->public;
}

vici_prompt_t *vici_prompt_create(vici_dispatcher_t *dispatcher)
{
	private_vici_prompt_t *this;
	INIT(this,
			.public = {
				.destroy = _destroy,
			},
		.dispatcher = dispatcher,
		.lock = mutex_create(MUTEX_TYPE_DEFAULT),
		.prompt_clients = linked_list_create(),
		.requests_in_progress = linked_list_create(),
		.cond = condvar_create(CONDVAR_TYPE_DEFAULT),
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.timeout = lib->settings->get_time(lib->settings, "%s.plugins.vici.prompt_timeout", PROMPT_TIMEOUT_MS, lib->ns),      
		.creds = mem_cred_create(),
		.enabled = FALSE,
	);
	this->cb = callback_cred_create_shared(callback_shared, this);

	lib->credmgr->add_set(lib->credmgr, &this->creds->set);
	lib->credmgr->add_set(lib->credmgr, &this->cb->set);

	manage_commands(this, TRUE);

	/* lib->credmgr->add_prompt(lib->credmgr, prompt, this); */

	return &this->public;
}