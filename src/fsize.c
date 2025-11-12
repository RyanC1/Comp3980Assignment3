#include "argumentsd.h"
#include "contextd.h"
#include "errors.h"
#include <ctype.h>
#include <p101_c/p101_stdlib.h>
#include <p101_c/p101_string.h>
#include <p101_convert/integer.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/p101_string.h>
#include <p101_posix/p101_unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t exit_flag    = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static volatile sig_atomic_t socket_close = 0;    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

static void           setup_signal_handlers(void);
static void           sig_handler(int signal);
static void           parse_arguments(const struct p101_env *env, struct p101_error *err, int argc, char *argv[], struct contextd *context);
static void           handle_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args);
static void           convert_arguments(const struct p101_env *env, struct p101_error *err, struct arguments *args);
_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message);

#define MSG_LEN 256    // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)

static void setup_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(struct sigaction));

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
#endif
    action.sa_handler = sig_handler;
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if(sigaction(SIGINT, &action, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

static void sig_handler(int signal)
{
    if(signal == SIGINT)
    {
        exit_flag = 1;
    }
    else if(signal == SIGPIPE)
    {
        socket_close = 1;
    }
}

int main(int argc, char *argv[])
{
    static struct p101_fsm_transition transitions[] = {

    };

    struct p101_error    *err;
    struct p101_env      *env;
    struct p101_fsm_info *fsm;
    p101_fsm_state_t      from_state;
    p101_fsm_state_t      to_state;
    struct p101_error    *fsm_err;
    struct p101_env      *fsm_env;
    struct argumentsd     args;
    struct contextd       ctx;

    setup_signal_handlers();

    err = p101_error_create(false);

    if(err == NULL)
    {
        ctx.exit_code = EXIT_FAILURE;
        goto done;
    }

    env = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_error;
    }

    fsm_err = p101_error_create(false);

    if(fsm_err == NULL)
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_env;
    }

    fsm_env = p101_env_create(err, true, NULL);

    if(p101_error_has_error(err))
    {
        ctx.exit_code = EXIT_FAILURE;
        goto free_fsm_error;
    }

    p101_memset(env, &args, 0, sizeof(args));
    p101_memset(env, &ctx, 0, sizeof(ctx));
    ctx.arguments       = &args;
    ctx.arguments->argc = argc;
    ctx.arguments->argv = argv;
    ctx.exit_code       = EXIT_SUCCESS;

    fsm = p101_fsm_info_create(env, err, "fsized-fsm", fsm_env, fsm_err, NULL);

    p101_fsm_run(fsm, &from_state, &to_state, &ctx, transitions, sizeof(transitions));
    p101_fsm_info_destroy(env, &fsm);

    free(fsm_env);

free_fsm_error:
    p101_error_reset(fsm_err);
    p101_free(env, fsm_err);

free_env:
    p101_free(env, env);

free_error:
    p101_error_reset(err);
    free(err);

done:
    return ctx.exit_code;
}

static void parse_arguments(const struct p101_env *env, struct p101_error *err, int argc, char *argv[], struct contextd *context)
{
    int opt;

    P101_TRACE(env);

    opterr = 0;

    while((opt = p101_getopt(env, argc, argv, ":hvVd:")) != -1 && p101_error_has_no_error(err))
    {
        switch(opt)
        {
            case 'h':
            {
                P101_ERROR_RAISE_USER(err, NULL, ERR_USAGE);
                break;
            }
            case ':':
            {
                char msg[MSG_LEN];

                snprintf(msg, sizeof msg, "Option '-%c' requires an argument.", optopt ? optopt : '?');
                P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
                break;
            }
            case '?':
            {
                char msg[MSG_LEN];

                if(isprint(optopt))
                {
                    snprintf(msg, sizeof msg, "Unknown option '-%c'.", optopt);
                }
                else
                {
                    snprintf(msg, sizeof msg, "Unknown option character 0x%02X.", (unsigned)(unsigned char)optopt);
                }

                P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
                break;
            }
            default:
            {
                char msg[MSG_LEN];

                snprintf(msg, sizeof msg, "Internal error: unhandled option '-%c' returned by getopt.", isprint(opt) ? opt : '?');
                P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
                break;
            }
        }
    }

    if(p101_error_has_no_error(err))
    {
        if(optind < argc)
        {
            char   msg[MSG_LEN];
            size_t off;

            off = 0;
            off += (size_t)snprintf(msg + off, sizeof msg - off, "Unexpected argument%s:", (argc - optind) > 1 ? "s" : "");

            for(int i = optind; i < argc && off < sizeof msg; ++i)
            {
                size_t rem;

                rem = sizeof msg - off; /* bytes left including NUL */

                if(rem <= 1)
                {
                    break; /* no room for anything */
                }

                /* append a single leading space if possible */
                msg[off++] = ' ';
                rem        = sizeof msg - off; /* recompute remaining space */

                if(rem > 0)
                {
                    /* copy at most rem-1 chars to leave room for the NUL */
                    size_t ncopy = p101_strnlen(env, argv[i], rem - 1);
                    p101_memcpy(env, msg + off, argv[i], ncopy);
                    off += ncopy;
                    msg[off] = '\0'; /* always NUL-terminate */
                }
            }

            msg[sizeof msg - 1] = '\0';
            P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
        }
    }
}

void check_arguments(const struct p101_env *env, struct p101_error *err, const struct arguments *args)
{
    P101_TRACE(env);

    if(args->delay_str == NULL || args->delay_str[0] == '\0')
    {
        P101_ERROR_RAISE_USER(err, "The delay is required.", ERR_USAGE);
        goto done;
    }

done:
    return;
}

void convert_arguments(const struct p101_env *env, struct p101_error *err, struct arguments *args)
{
    P101_TRACE(env);

    args->delay = p101_parse_unsigned_int(env, err, args->delay_str, 0);

    if(p101_error_has_error(err))
    {
        P101_ERROR_RAISE_USER(err, "delay must be a positive integer.", ERR_USAGE);
        goto done;
    }

done:
    return;
}

_Noreturn static void usage(const struct p101_env *env, const char *program_name, int exit_code, const char *message)
{
    P101_TRACE(env);

    if(message)
    {
        fprintf(stderr, "%s\n\n", message);
    }

    fprintf(stderr, "Usage: %s [-h] [-v] -d <delay>\n", program_name);
    fputs("Options:\n", stderr);
    fputs("  -h                Display this help message and exit\n", stderr);
    fputs("  -v                Enable verbose tracing\n", stderr);
    fputs("  -d <delay>        delay in seconds (required)\n", stderr);
    exit(exit_code);
}
