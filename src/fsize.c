#include "arguments.h"
#include "context.h"
#include "errors.h"
#include "request.h"
#include "util.h"
#include <ctype.h>
#include <fcntl.h>
#include <p101_c/p101_stdlib.h>
#include <p101_c/p101_string.h>
#include <p101_convert/integer.h>
#include <p101_fsm/fsm.h>
#include <p101_posix/p101_unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>

enum states
{
    PARSE_ARGS = P101_FSM_USER_START,
    HANDLE_ARGS,
    CREATE_REQUESTS,
    USAGE,
    CLEANUP,
};

// static void             setup_signal_handlers(void);
// static void             sig_handler(int signal);
static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t create_requests(const struct p101_env *env, struct p101_error *err, void *context);
static void            *request_details(void *data);
static void             random_sleep(unsigned int min, unsigned int max);
static void             receive_response(const struct request *request, int server_fd);
static void             thread_print(const struct request *request, const char *message);
static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *context);
static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *context);

#define MSG_LEN 256              // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)
#define MILLI_TO_NANO 1000000    // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)
#define MILLI_TO_SEC 1000        // NOLINT(cppcoreguidelines-macro-to-enum, modernize-macro-to-enum)

int main(int argc, char *argv[])
{
    static struct p101_fsm_transition transitions[] = {
        {P101_FSM_INIT,   PARSE_ARGS,      parse_arguments },
        {PARSE_ARGS,      HANDLE_ARGS,     handle_arguments},
        {PARSE_ARGS,      USAGE,           usage           },
        {HANDLE_ARGS,     CREATE_REQUESTS, create_requests },
        {HANDLE_ARGS,     USAGE,           usage           },
        {HANDLE_ARGS,     CLEANUP,         cleanup         },
        {CREATE_REQUESTS, CLEANUP,         cleanup         },
        {CLEANUP,         P101_FSM_EXIT,   NULL            }
    };

    struct p101_error    *err;
    struct p101_env      *env;
    struct p101_fsm_info *fsm;
    p101_fsm_state_t      from_state;
    p101_fsm_state_t      to_state;
    struct p101_error    *fsm_err;
    struct p101_env      *fsm_env;
    struct arguments      args;
    struct context        ctx;

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

    srand((unsigned int)getpid());
    p101_memset(env, &args, 0, sizeof(args));
    p101_memset(env, &ctx, 0, sizeof(ctx));
    ctx.arguments       = &args;
    ctx.arguments->argc = argc;
    ctx.arguments->argv = argv;
    ctx.exit_code       = EXIT_SUCCESS;

    fsm = p101_fsm_info_create(env, err, "fsize-fsm", fsm_env, fsm_err, NULL);

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

static p101_fsm_state_t parse_arguments(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context  *ctx;
    p101_fsm_state_t next_state;
    int              opt;

    P101_TRACE(env);
    ctx                          = (struct context *)context;
    ctx->arguments->program_name = ctx->arguments->argv[0];
    next_state                   = HANDLE_ARGS;
    opterr                       = 0;

    while((opt = p101_getopt(env, ctx->arguments->argc, ctx->arguments->argv, ":hs:m:M:")) != -1 && p101_error_has_no_error(err))
    {
        switch(opt)
        {
            case 'h':
            {
                next_state = USAGE;
                break;
            }
            case 's':
            {
                if(ctx->arguments->server_path != NULL)
                {
                    P101_ERROR_RAISE_USER(err, "Option -s specified more than once.", ERR_USAGE);
                }
                else
                {
                    ctx->arguments->server_path = optarg;
                }
                break;
            }
            case 'm':
            {
                if(ctx->arguments->min_delay_str != NULL)
                {
                    P101_ERROR_RAISE_USER(err, "Option -m specified more than once.", ERR_USAGE);
                }
                else
                {
                    ctx->arguments->min_delay_str = optarg;
                }
                break;
            }
            case 'M':
            {
                if(ctx->arguments->max_delay_str != NULL)
                {
                    P101_ERROR_RAISE_USER(err, "Option -M specified more than once.", ERR_USAGE);
                }
                else
                {
                    ctx->arguments->max_delay_str = optarg;
                }
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

    if(p101_error_has_no_error(err) && next_state != USAGE)
    {
        if(optind >= ctx->arguments->argc)
        {
            P101_ERROR_RAISE_USER(err, "<file-paths> must be specified.", ERR_USAGE);
        }
        else
        {
            ctx->arguments->num_files = ctx->arguments->argc - optind;
            ctx->arguments->files     = &ctx->arguments->argv[optind];
        }
    }

    if(p101_error_is_error(err, P101_ERROR_USER, ERR_USAGE))
    {
        next_state = USAGE;
    }

    return next_state;
}

p101_fsm_state_t handle_arguments(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context    *ctx;
    p101_fsm_state_t   next_state;
    struct sockaddr_un addr;

    P101_TRACE(env);
    ctx        = (struct context *)context;
    next_state = CREATE_REQUESTS;

    if(ctx->arguments->server_path == NULL || ctx->arguments->server_path[0] == '\0')
    {
        P101_ERROR_RAISE_USER(err, "-s <server-path> must be specified.", ERR_USAGE);
        goto done;
    }

    if(ctx->arguments->min_delay_str == NULL || ctx->arguments->min_delay_str[0] == '\0')
    {
        P101_ERROR_RAISE_USER(err, "-m <min-delay> must be specified", ERR_USAGE);
        goto done;
    }

    if(ctx->arguments->max_delay_str == NULL || ctx->arguments->max_delay_str[0] == '\0')
    {
        P101_ERROR_RAISE_USER(err, "-M <max-delay> must be specified", ERR_USAGE);
        goto done;
    }

    ctx->min_delay = p101_parse_unsigned_int(env, err, ctx->arguments->min_delay_str, 0);

    if(p101_error_has_error(err))
    {
        p101_error_reset(err);
        P101_ERROR_RAISE_USER(err, "Could not parse the minimum delay.", ERR_USAGE);
        goto done;
    }

    ctx->max_delay = p101_parse_unsigned_int(env, err, ctx->arguments->max_delay_str, 0);

    if(p101_error_has_error(err))
    {
        p101_error_reset(err);
        P101_ERROR_RAISE_USER(err, "Could not parse the maximum delay.", ERR_USAGE);
        goto done;
    }

    if(ctx->max_delay < ctx->min_delay)
    {
        P101_ERROR_RAISE_USER(err, "Minimum delay greater than maximum delay.", ERR_USAGE);
        goto done;
    }

    if(init_un_addr(&addr, ctx->arguments->server_path) == -1)
    {
        P101_ERROR_RAISE_USER(err, "Socket path too long to accurately connect.", ERR_SOCKET);
        goto done;
    }

    ctx->addr = addr;

done:
    if(p101_error_is_error(err, P101_ERROR_USER, ERR_USAGE))
    {
        next_state = USAGE;
    }
    else if(p101_error_has_error(err))
    {
        next_state = CLEANUP;
    }

    return next_state;
}

static p101_fsm_state_t create_requests(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context *ctx;
    pthread_mutex_t print_mutex;
    pthread_t       num_threads;
    atomic_size_t   failed_threads;
    pthread_t      *threads;
    struct request *requests;

    P101_TRACE(env);
    ctx = (struct context *)context;

    threads  = NULL;
    requests = NULL;
    atomic_store(&failed_threads, 0);
    num_threads = (pthread_t)ctx->arguments->num_files;

    threads = (pthread_t *)p101_malloc(env, err, num_threads * sizeof(pthread_t));

    if(p101_error_has_error(err))
    {
        p101_error_reset(err);
        P101_ERROR_RAISE_USER(err, "Could not malloc thread ids", ERR_OTHER);
        goto done;
    }

    requests = (struct request *)p101_malloc(env, err, num_threads * sizeof(struct request));

    if(p101_error_has_error(err))
    {
        p101_error_reset(err);
        P101_ERROR_RAISE_USER(err, "Could not malloc requests", ERR_OTHER);
        goto done;
    }

    for(pthread_t i = 0; i < num_threads; i++)
    {
        memset(&requests[i], 0, sizeof(struct request));
        requests[i].addr           = &ctx->addr;
        requests[i].min_delay      = &ctx->min_delay;
        requests[i].max_delay      = &ctx->max_delay;
        requests[i].filepath       = ctx->arguments->files[i];
        requests[i].print_mutex    = &print_mutex;
        requests[i].failed_threads = &failed_threads;

        pthread_create(&threads[i], NULL, request_details, &requests[i]);
    }

    for(pthread_t i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    if(atomic_load(&failed_threads) != 0)
    {
        char msg[MSG_LEN];

        snprintf(msg, sizeof msg, "%lu threads failed to close their sever connections.", atomic_load(&failed_threads));
        P101_ERROR_RAISE_USER(err, msg, ERR_USAGE);
    }

    if(pthread_mutex_destroy(&print_mutex) != 0)
    {
        p101_error_reset(err);
        P101_ERROR_RAISE_USER(err, "Could not destory client mutex", ERR_USAGE);
    }

done:
    free(threads);
    free(requests);
    return CLEANUP;
}

static void *request_details(void *data)
{
    struct request *request;
    uint16_t        filepath_length;
    int             server_fd;

    request = (struct request *)data;
    random_sleep(*request->min_delay, *request->max_delay);

    server_fd = create_un_socket();

    if(server_fd == -1)
    {
        thread_print(request, "Client exit, failed to connect create socket.");
        goto done;
    }

    if(connect(server_fd, (struct sockaddr *)request->addr, sizeof(*request->addr)) == -1)
    {
        thread_print(request, "Client exit, failed to connect to server.");
        goto done;
    }

    if(strlen(request->filepath) + 1 > UINT16_MAX)
    {
        thread_print(request, "Client exit, filepath too long to send to server.");
        goto done;
    }

    filepath_length = (uint16_t)(strlen(request->filepath) + 1);
    safe_write(server_fd, &filepath_length, sizeof(uint16_t));
    safe_write(server_fd, request->filepath, filepath_length);

    shutdown(server_fd, SHUT_WR);

    receive_response(request, server_fd);

done:
    if(server_fd > 0 && close(server_fd) == -1)
    {
        atomic_fetch_add(request->failed_threads, 1);
    }

    return NULL;
}

static void random_sleep(unsigned int min, unsigned int max)
{
    unsigned int    time_ms;
    struct timespec req;

    time_ms = (unsigned int)rand() % (max + 1 - min) + min;    // NOLINT(cert-msc30-c, cert-msc50-cpp)

    req.tv_sec  = time_ms / (long)MILLI_TO_SEC;
    req.tv_nsec = (time_ms % (long)MILLI_TO_SEC) * (long)MILLI_TO_NANO;

    nanosleep(&req, NULL);
}

static void receive_response(const struct request *request, int server_fd)
{
    uint16_t response_length;
    char    *server_response;

    server_response = NULL;

    if(safe_read(server_fd, &response_length, sizeof(uint16_t), true) < 0)
    {
        thread_print(request, "Client exit, could not parse server response length.");
        goto done;
    }

    server_response = (char *)malloc(response_length);

    if(server_response == NULL)
    {
        thread_print(request, "Client exit, could not allocate memory for server response.");
        goto done;
    }

    if(safe_read(server_fd, server_response, response_length, true) < 0)
    {
        thread_print(request, "Client exit, could not parse server response.");
    }
    else
    {
        thread_print(request, server_response);
    }

done:
    free(server_response);
}

static void thread_print(const struct request *request, const char *message)
{
    pthread_mutex_lock(request->print_mutex);
    printf("Response for: %s\n     %s\n", request->filepath, message);
    pthread_mutex_unlock(request->print_mutex);
}

static p101_fsm_state_t usage(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context *ctx;

    P101_TRACE(env);
    ctx = (struct context *)context;

    if(p101_error_has_error(err))
    {
        const char *msg;
        msg = p101_error_get_message(err);

        if(msg != NULL)
        {
            fputs(msg, stderr);
            fputc('\n', stderr);
        }

        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;
    }

    fprintf(stderr, "Usage: %s [-h] -s <server-path> -m <min-delay> -M <max-delay> <file-paths>...\n", ctx->arguments->program_name);
    fputs("Options:\n", stderr);
    fputs("  -h                Display this help message and exit\n", stderr);
    fputs("  -s <server-path>  Path to the domain socket (required)\n", stderr);
    fputs("  -m <min-delay>    Minimum delay in milliseconds (required)\n", stderr);
    fputs("  -M <max-delay>    Maximum delay in milliseconds (required)\n", stderr);
    fputs("  <file_paths>...   One or more files to analyze (required)\n", stderr);

    return CLEANUP;
}

static p101_fsm_state_t cleanup(const struct p101_env *env, struct p101_error *err, void *context)
{
    struct context *ctx;

    P101_TRACE(env);
    ctx = (struct context *)context;

    if(p101_error_has_error(err))
    {
        const char *msg;
        msg = p101_error_get_message(err);

        if(msg != NULL)
        {
            fputs(msg, stderr);
            fputc('\n', stderr);
        }

        p101_error_reset(err);
        ctx->exit_code = EXIT_FAILURE;
    }

    return P101_FSM_EXIT;
}
