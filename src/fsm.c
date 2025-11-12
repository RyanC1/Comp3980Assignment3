#include "fsm.h"
#include "errors.h"
#include <p101_fsm/fsm.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static p101_fsm_state_t a(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t b(const struct p101_env *env, struct p101_error *err, void *arg);
static p101_fsm_state_t c(const struct p101_env *env, struct p101_error *err, void *arg);
static void             will_change_state_notifier_func(const struct p101_env *env, struct p101_error *err, const struct p101_fsm_info *info, p101_fsm_state_t from_state_id, p101_fsm_state_t to_state_id);
static void             did_change_state_notifier_func(const struct p101_env *env, struct p101_error *err, const struct p101_fsm_info *info, p101_fsm_state_t from_state_id, p101_fsm_state_t to_state_id, p101_fsm_state_t next_state_id);
static p101_fsm_state_t bad_change_state_notifier_func(const struct p101_env *env, struct p101_error *err, const struct p101_fsm_info *info, p101_fsm_state_t from_state_id, p101_fsm_state_t to_state_id);

enum states
{
    A = P101_FSM_USER_START,    // 2
    B,
    C,
};

int run_fsm(const struct p101_env *env, struct p101_error *err, const struct arguments *args)
{
    struct p101_error                *fsm_err;
    const struct p101_env            *fsm_env;
    struct p101_fsm_info             *fsm;
    p101_fsm_state_t                  from_state;
    p101_fsm_state_t                  to_state;
    static struct p101_fsm_transition transitions[] = {
        {P101_FSM_INIT, A,             a   },
        {A,             B,             b   },
        {B,             C,             c   },
        {C,             P101_FSM_EXIT, NULL}
    };
    unsigned int delay;

    P101_TRACE(env);
    fsm_err = p101_error_create(args->fsm_verbose);
    fsm_env = p101_env_create(fsm_err, true, NULL);
    fsm     = p101_fsm_info_create(env, err, "fsm", fsm_env, fsm_err, NULL);

    if(p101_error_has_error(err))
    {
        goto done;
    }

    if(args->fsm_verbose)
    {
        p101_fsm_info_set_bad_change_state_handler(fsm, bad_change_state_notifier_func);
        p101_fsm_info_set_will_change_state_notifier(fsm, will_change_state_notifier_func);
        p101_fsm_info_set_did_change_state_notifier(fsm, did_change_state_notifier_func);
    }

    delay = args->delay;
    p101_fsm_run(fsm, &from_state, &to_state, &delay, transitions, sizeof(transitions));
done:
    p101_fsm_info_destroy(env, &fsm);

    if(p101_error_has_error(fsm_err))
    {
        const char *msg = p101_error_get_message(fsm_err);

        P101_ERROR_RAISE_USER(err, msg, ERR_FSM);
        p101_error_reset(fsm_err);
    }

    return EXIT_SUCCESS;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static p101_fsm_state_t a(const struct p101_env *env, struct p101_error *err, void *arg)
{
    const unsigned int *delay;

    P101_TRACE(env);
    delay = (unsigned int *)arg;
    printf("a called\n");
    sleep(*delay);

    return B;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static p101_fsm_state_t b(const struct p101_env *env, struct p101_error *err, void *arg)
{
    const unsigned int *delay;

    P101_TRACE(env);
    delay = (unsigned int *)arg;
    printf("b called\n");
    sleep(*delay);

    return C;
}

#pragma GCC diagnostic pop

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static p101_fsm_state_t c(const struct p101_env *env, struct p101_error *err, void *arg)
{
    const unsigned int *delay;

    P101_TRACE(env);
    delay = (unsigned int *)arg;
    printf("c called\n");
    sleep(*delay);

    return P101_FSM_EXIT;
}

#pragma GCC diagnostic pop

static void will_change_state_notifier_func(const struct p101_env *env, struct p101_error *err, const struct p101_fsm_info *info, p101_fsm_state_t from_state_id, p101_fsm_state_t to_state_id)
{
    P101_TRACE(env);
    printf("%s will change from %d to %d\n", p101_fsm_info_get_name(env, info), from_state_id, to_state_id);
}

static void did_change_state_notifier_func(const struct p101_env *env, struct p101_error *err, const struct p101_fsm_info *info, p101_fsm_state_t from_state_id, p101_fsm_state_t to_state_id, p101_fsm_state_t next_state_id)
{
    P101_TRACE(env);
    printf("%s did change from %d to %d\n", p101_fsm_info_get_name(env, info), from_state_id, to_state_id);
}

static p101_fsm_state_t bad_change_state_notifier_func(const struct p101_env *env, struct p101_error *err, const struct p101_fsm_info *info, p101_fsm_state_t from_state_id, p101_fsm_state_t to_state_id)
{
    P101_TRACE(env);
    printf("%s can't change from %d to %d\n", p101_fsm_info_get_name(env, info), from_state_id, to_state_id);

    return to_state_id;
}
