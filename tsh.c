/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Yuhong YAO <yuhongy@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

volatile sig_atomic_t pid;

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief evaluate the command line argument and execute the inputs
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // Parse command line
    parse_result = parseline(cmdline, &token);
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    sigset_t mask, prev_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTSTP);

    // Implement builtin commands here.
    if (token.builtin == BUILTIN_QUIT) {
        // handle builtin command
        // sio_printf("Built in quit recognized, exiting the shell.\n");
        exit(0);
    } else if (token.builtin == BUILTIN_JOBS) {
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);
        list_jobs(1);
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    } else if (token.builtin == BUILTIN_NONE) {
        // handle external command
        // Block signals before fork
        sigprocmask(SIG_BLOCK, &mask, &prev_mask);

        /* figure 8.24 csapp*/
        if ((pid = fork()) == 0) { // child process
            sigprocmask(SIG_SETMASK, &prev_mask,
                        NULL); // unblock child process signals
            setpgid(0, 0);     // in foreground process group
            if (execve(token.argv[0], token.argv, environ) < 0) {
                sio_printf("%s: No such file or directory\n", token.argv[0]);
                exit(0);
            }
        }

        /* Parent waits for foreground job to terminate */
        jid_t job_id = 0;
        if (parse_result == PARSELINE_FG) {
            sigprocmask(SIG_BLOCK, &mask, NULL);
            job_id = add_job(pid, FG, cmdline);
            while (fg_job() != 0) {
                sigsuspend(&prev_mask);
            }
            sigprocmask(SIG_SETMASK, &prev_mask, NULL); // optionally unblock

        } else if (parse_result == PARSELINE_BG) { // background job handler
            sigprocmask(SIG_BLOCK, &mask, NULL);
            job_id = add_job(pid, BG, cmdline);
            sigprocmask(SIG_SETMASK, &prev_mask, NULL);
            sio_printf("[%d] (%d) %s\n", job_id, pid, cmdline);
        }

        // Unblock all signals
        sigprocmask(SIG_SETMASK, &prev_mask, NULL);
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief handles SIGCHLD signal
 *
 * This handler is called when SIGCHLD signal is received, meaning a child
 * process has stopped or terminated. The handler reaps any child process that
 * has been stopped or terminated. It deletes the job from joblist if terminated
 * or change the state in job list if stopped.
 */
void sigchld_handler(int sig) {
    int olderrno = errno; // save the current errno
    int status;
    sigset_t mask, prev;
    sigfillset(&mask);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        if (WIFEXITED(status)) { // child terminated normally
            delete_job(job_from_pid(
                pid)); // delete the child from job list if terminated
        } else if (WIFSTOPPED(status)) { // child is stopped
            sio_printf("Job [%d] (%d) stopped by signal %d\n",
                       job_from_pid(pid), pid, WSTOPSIG(status));
            job_set_state(job_from_pid(pid), ST);
        } else if (WIFSIGNALED(status)) { // child is terminated
            sio_printf("Job [%d] (%d) terminated by signal %d\n",
                       job_from_pid(pid), pid, WTERMSIG(status));
            delete_job(job_from_pid(pid));
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
    }
    errno = olderrno; // restore the old errno
}

/**
 * @brief Handles SIGINT (ctrl + c)
 *
 * This handler is called when the shell receives a SIGINT signal, it will catch
 * the signal and forward to the entire process group that contains the
 * foreground job.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t job_id = fg_job();
    if (job_id != 0) {
        pid = job_get_pid(job_id);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        kill(-pid, SIGINT); // pid < 0, kills every process in pg
    }
    errno = olderrno;
}

/**
 * @brief Handles SIGTSTP (ctrl + z)
 *
 * This function is called when the shell receives a SIGTSTP signal, it is
 * similar to SIGINT handler, except it will be able to continue after resume
 * after receive a SIGCONT signal
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask, prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t job_id = fg_job();
    if (job_id != 0) {
        pid = job_get_pid(job_id);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        kill(-pid, SIGTSTP); // pid < 0, kills every process in pg
    }
    errno = olderrno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
