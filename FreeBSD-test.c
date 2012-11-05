/*
 *  FreeBSD System Call Test
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <utime.h>
#include <time.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include <dirent.h>
#include <setjmp.h>
#include <sys/shm.h>
#include <sys/resource.h>
#include <signal.h>
#include <semaphore.h>
#include <netdb.h>
#include <sys/file.h>
#include <poll.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define TESTPATH "/tmp/freebsd-test.tmp"
#define TESTPORT 7654
#define STACK_SIZE 16384

#define ARCH_X86 0
#define ARCH_MIPS 1
#define ARCH_SPARC 2 

#define ECHO_PORT 7

void error1(const char *filename, int line, const char *function, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    //fprintf(stderr, "Test Failed in file %s, funtion %s(), line %d: \n", filename, function, line);
    char buf[512];
	sprintf(buf, "Test Failed in file %s, function %s(), line %d: \n", filename, function, line); 
	perror(buf);
	vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");


    va_end(ap);
    exit(1);
}

int __chk_error(const char *filename, int line, const char *function, int ret)
{
    if (ret < 0) {
        error1(filename, line, function, "%m (ret=%d, errno=%d)",
               ret, errno);
    }
    return ret;
}

#define error(fmt, ...) error1(__FILE__, __LINE__, __func__, fmt, ## __VA_ARGS__)

#define chk_error(ret) __chk_error(__FILE__, __LINE__, __func__, (ret))

/*
 * ******************************************************/

#define FILE_BUF_SIZE 300

void test_file(void)
{
    int fd, i, len, ret;
    uint8_t buf[FILE_BUF_SIZE];
    uint8_t buf2[FILE_BUF_SIZE];
    uint8_t buf3[FILE_BUF_SIZE];
    char cur_dir[1024];
    struct stat st;
    struct iovec vecs[2];
    DIR *dir;
    struct dirent *de;
	
	struct timeval times[2]; 
	
    /* clean up, just in case */
    unlink(TESTPATH "/file1");
    unlink(TESTPATH "/file2");
    unlink(TESTPATH "/file3");
    rmdir(TESTPATH);
	
    if (getcwd(cur_dir, sizeof(cur_dir)) == NULL)
        error("getcwd");
	
    chk_error(mkdir(TESTPATH, 0755));
	
    chk_error(chdir(TESTPATH));
	
    /* open/read/write/close/readv/writev/lseek */
	
    fd = chk_error(open("file1", O_WRONLY | O_TRUNC | O_CREAT, 0644));
    for(i=0;i < FILE_BUF_SIZE; i++)
        buf[i] = i;
    len = chk_error(write(fd, buf, FILE_BUF_SIZE / 2));
    if (len != (FILE_BUF_SIZE / 2))
        error("write");
    vecs[0].iov_base = buf + (FILE_BUF_SIZE / 2);
    vecs[0].iov_len = 16;
    vecs[1].iov_base = buf + (FILE_BUF_SIZE / 2) + 16;
    vecs[1].iov_len = (FILE_BUF_SIZE / 2) - 16;
    len = chk_error(writev(fd, vecs, 2));
    if (len != (FILE_BUF_SIZE / 2))
		error("writev");
    chk_error(close(fd));
	
    chk_error(rename("file1", "file2"));
	
    fd = chk_error(open("file2", O_RDONLY));
	
    len = chk_error(read(fd, buf2, FILE_BUF_SIZE));
    if (len != FILE_BUF_SIZE)
        error("read");
    if (memcmp(buf, buf2, FILE_BUF_SIZE) != 0)
        error("memcmp");
	
#define FOFFSET 16
    ret = chk_error(lseek(fd, FOFFSET, SEEK_SET));
    if (ret != 16)
       error("lseek");
    vecs[0].iov_base = buf3;
    vecs[0].iov_len = 32;
	vecs[1].iov_base = buf3 + 32;
    vecs[1].iov_len = FILE_BUF_SIZE - FOFFSET - 32;
    len = chk_error(readv(fd, vecs, 2));
    if (len != FILE_BUF_SIZE - FOFFSET)
        error("readv");
    if (memcmp(buf + FOFFSET, buf3, FILE_BUF_SIZE - FOFFSET) != 0)
        error("memcmp");
	
    chk_error(close(fd));
    	
    /* access */
    chk_error(access("file2", R_OK));
	
    /* stat/chmod/utime/truncate */
	
    chk_error(chmod("file2", 0600));
    
	/* set access time */
	times[0].tv_sec = 1005;
	times[0].tv_usec = 0;

	/* set modification time */
	times[1].tv_sec = 456;
	times[1].tv_usec = 0;
	
    chk_error(truncate("file2", 100));
    chk_error(utimes("file2", times));
    chk_error(stat("file2", &st));
	if (st.st_size != 100) 
        error("stat size");
    if (!S_ISREG(st.st_mode))
        error("stat mode");
    if ((st.st_mode & 0777) != 0600)
        error("stat mode2");
    if (st.st_atime != 1005 ||
        st.st_mtime != 456)
		error("stat time");
	
    chk_error(stat(TESTPATH, &st));
    if (!S_ISDIR(st.st_mode))
        error("stat mode");

    /* fstat */
    fd = chk_error(open("file2", O_RDWR));
    chk_error(ftruncate(fd, 50));
    chk_error(fstat(fd, &st));
    chk_error(close(fd));
	
    if (st.st_size != 50)
        error("stat size");
    if (!S_ISREG(st.st_mode))
        error("stat mode");

    /* symlink/lstat */
    chk_error(symlink("file2", "file3"));
    chk_error(lstat("file3", &st));
    if (!S_ISLNK(st.st_mode))
        error("stat mode");

    /* getdents */
    dir = opendir(TESTPATH);
    if (!dir)
        error("opendir");
    len = 0;
    for(;;) {
        de = readdir(dir);
		if (!de)
            break;
        if (strcmp(de->d_name, ".") != 0 &&
            strcmp(de->d_name, "..") != 0 &&
            strcmp(de->d_name, "file2") != 0 &&
            strcmp(de->d_name, "file3") != 0)
            error("readdir");
        len++;
    }
    closedir(dir);
    if (len != 4)
	{
        error("readdir");
	}

    chk_error(unlink("file3"));
    chk_error(unlink("file2"));
    chk_error(chdir(cur_dir));
    chk_error(rmdir(TESTPATH));

}

void test_fork(void)
{
    int pid, status;
	
    pid = chk_error(fork());

    if (pid == 0) {
        /* child */
        exit(2);
    }
    chk_error(waitpid(pid, &status, 0));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 2)
        error("waitpid status=0x%x", status);
}

void test_time(void)
{
    struct timeval tv, tv2;
    struct timespec ts, rem;
    struct rusage rusg1, rusg2;
    int ti, i;
	
    chk_error(gettimeofday(&tv, NULL));
    rem.tv_sec = 1;
    ts.tv_sec = 0;
    ts.tv_nsec = 20 * 1000000;
    chk_error(nanosleep(&ts, &rem));
    if (rem.tv_sec != 1)
        error("nanosleep");
    chk_error(gettimeofday(&tv2, NULL));
    ti = tv2.tv_sec - tv.tv_sec;
    if (ti >= 2)
        error("gettimeofday");
	
	chk_error(getrusage(RUSAGE_SELF, &rusg1));
    for(i = 0;i < 10000; i++);
    chk_error(getrusage(RUSAGE_SELF, &rusg2));
    if ((rusg2.ru_utime.tv_sec - rusg1.ru_utime.tv_sec) < 0 ||
        (rusg2.ru_stime.tv_sec - rusg1.ru_stime.tv_sec) < 0)
        error("getrusage");
}

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;
	
    if (buf_size <= 0)
        return;
	
    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

/* strcat and truncate. */
char *pstrcat(char *buf, int buf_size, const char *s)
{
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}

int server_socket(void)
{
    int val, fd;
    struct sockaddr_in sockaddr;

    /* server socket */
    fd = chk_error(socket(PF_INET, SOCK_STREAM, 0));
	
    val = 1;
    chk_error(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)));
	
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(TESTPORT);
    sockaddr.sin_addr.s_addr = 0;
    chk_error(bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)));
    chk_error(listen(fd, 0));
    return fd;
	
}

int client_socket(void)
{
    int fd;
    struct sockaddr_in sockaddr;
	
    /* server socket */
    fd = chk_error(socket(PF_INET, SOCK_STREAM, 0));
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(TESTPORT);
    inet_aton("127.0.0.1", &sockaddr.sin_addr);
    chk_error(connect(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)));
    return fd;
}

const char socket_msg[] = "hello socket\n";

void test_socket(void)
{
    int server_fd, client_fd, fd, pid, ret, val;
    struct sockaddr_in sockaddr;
    socklen_t len;
    char buf[512];
	
    server_fd = server_socket();

    /* test a few socket options */
    len = sizeof(val);
    chk_error(getsockopt(server_fd, SOL_SOCKET, SO_TYPE, &val, &len));
    
	//printf("Socket: %d\n", val);
	if (val != SOCK_STREAM)
        error("getsockopt");
	
    pid = chk_error(fork());

    if (pid == 0) {
		//sleep(2);
        client_fd = client_socket();
        send(client_fd, socket_msg, sizeof(socket_msg), 0);
        close(client_fd);
        exit(0);
    }
    len = sizeof(sockaddr);

	fflush(__stdoutp);
    fd = accept(server_fd, (struct sockaddr *)&sockaddr, &len);

	fflush(__stdoutp);
    
	ret = chk_error(recv(fd, buf, sizeof(buf), 0));
    if (ret != sizeof(socket_msg))
        error("recv");
    if (memcmp(buf, socket_msg, sizeof(socket_msg)) != 0)
        error("socket_msg");
    chk_error(close(fd));
    chk_error(close(server_fd));
}

#define WCOUNT_MAX 512

void test_pipe(void)
{
    fd_set rfds, wfds;
	struct pollfd poll_set[2]; 
    int fds[2], fd_max, ret;
    uint8_t ch;
    int wcount, rcount;
	
   	chk_error(pipe(fds));
    chk_error(fcntl(fds[0], F_SETFL, O_NONBLOCK));
    chk_error(fcntl(fds[1], F_SETFL, O_NONBLOCK));
    wcount = 0;
    rcount = 0;

	/* one byte test */

	ch = 'x';
	chk_error(write(fds[1], &ch, 1));
	ch = 'b';
	chk_error(read(fds[0], &ch, 1));
    
	if(ch != 'x')
	{
		error("pipe");
	}

	/* many bytes test */

	for(;;) {
        FD_ZERO(&rfds);
        fd_max = fds[0];
        FD_SET(fds[0], &rfds);
		
        FD_ZERO(&wfds);
        FD_SET(fds[1], &wfds);
        if (fds[1] > fd_max)
            fd_max = fds[1];
		
        ret = chk_error(select(fd_max + 1, &rfds, &wfds, NULL, NULL));
        if (ret > 0) {
            if (FD_ISSET(fds[0], &rfds)) {
				ch = 'x';
                chk_error(read(fds[0], &ch, 1));
				rcount++;

				if(ch != 'a')
					error("read from pipe give wrong character");

                if (rcount >= WCOUNT_MAX)
                    break;
            }
            if (FD_ISSET(fds[1], &wfds)) {
                ch = 'a';
                chk_error(write(fds[1], &ch, 1));
                wcount++;
            }
        }
    }

	wcount = 0;
	rcount = 0;

	/* same test using poll instead of select */
	for(;;) {
		poll_set[0].fd = fds[0];
		poll_set[1].fd = fds[1];
		poll_set[0].events = POLLRDNORM;
		poll_set[1].events = POLLWRNORM;
		poll_set[1].revents = poll_set[0].revents = 0; 

		ret = chk_error(poll( poll_set, 2, 500));
		if(ret > 0)
		{

			if(poll_set[0].revents & POLLRDNORM)
			{
				ch = 'x'; 
				chk_error(read(fds[0], &ch, 1));
				rcount++;

				if(ch != 'a')
					error("read from pipe gives wrong character");

				if (rcount >= WCOUNT_MAX)
					break;
			}
			if(poll_set[1].revents & POLLWRNORM)
			{
				ch = 'a';
				chk_error(write(fds[1], &ch, 1));
				wcount++;
			}
		}
	}

    chk_error(close(fds[0]));
    chk_error(close(fds[1]));
}

int thread1_res;
int thread2_res;

int thread1_func(void *arg)
{
    int i;
    for(i=0;i<5;i++) {
        thread1_res++;
        usleep(10 * 1000);
    }
    return 0;
}

int thread2_func(void *arg)
{
    int i;
    for(i=0;i<6;i++) {
        thread2_res++;
        usleep(10 * 1000);
    }
    return 0;
}

/***********************************/

volatile int alarm_count;
volatile int parent_sig; 
jmp_buf jmp_env;

void sig_alarm(int sig)
{
    if (sig != SIGALRM)
        error("signal");

	alarm_count++;
}

void sig_segv(int sig, siginfo_t *info, void *puc)
{
    if (sig != SIGSEGV)
        error("signal");
	longjmp(jmp_env, 1);
}

void sig_user1(int sig)
{
	parent_sig++;
}

void test_signal(void)
{
    struct sigaction act;
    struct itimerval it, oit;
	
    /* timer test */
	
    alarm_count = 0;
	
    act.sa_handler = sig_alarm;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    chk_error(sigaction(SIGALRM, &act, NULL));
	
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 10 * 1000;
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 10 * 1000;
    chk_error(setitimer(ITIMER_REAL, &it, NULL));
	sleep(1);
    chk_error(getitimer(ITIMER_REAL, &oit));
    if (oit.it_interval.tv_sec != it.it_interval.tv_sec ||
        oit.it_interval.tv_usec !=  it.it_interval.tv_usec)
	{ 
        error("itimer"); 
	}

    while (alarm_count < 5) {
        usleep(10 * 1000);
    }

    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 0;
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    memset(&oit, 0xff, sizeof(oit));
    chk_error(setitimer(ITIMER_REAL, &it, &oit));

	// make sure alarm is really off
	usleep(10 * 1000);
	if(alarm_count > 5)
		error("setitimer");

    if (oit.it_interval.tv_sec != 0 ||
        oit.it_interval.tv_usec != 10 * 1000)
    {
		error("setitimer");
	}
	
	/* SIGSEGV test */
    act.sa_sigaction = sig_segv;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    chk_error(sigaction(SIGSEGV, &act, NULL));
    if (setjmp(jmp_env) == 0) {
        *(uint8_t *)0 = 0;
    }
	
    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    chk_error(sigaction(SIGSEGV, &act, NULL));

	/* sending signals to other processes */

	int parent_pid, pid;

	signal(SIGUSR1, sig_user1);

	parent_sig = 0;
	parent_pid = getpid();
	pid = chk_error(fork());

	if(pid == 0)
	{
		kill(parent_pid, SIGUSR1 );
		exit(0);
	}

	pause();

	if(parent_sig != 1)
	{
		error("signal");
	}
}

#define SHM_SIZE 32768

void test_shm(void)
{
    void *ptr;
    int shmid;
	
    shmid = chk_error(shmget(IPC_PRIVATE, SHM_SIZE, IPC_CREAT | 0777));
    ptr = shmat(shmid, NULL, 0);
    if (!ptr)
        error("shmat");
	
    memset(ptr, 0, SHM_SIZE);
	
    chk_error(shmctl(shmid, IPC_RMID, 0));
    chk_error(shmdt(ptr));
}

void test_uid(void)
{
	gid_t child_pid, wait_pid;
	int status;

	child_pid = fork();
	if( child_pid == -1 )
	{
		error("fork");	
	}
	else if ( child_pid == 0)
	{
		/* child */
		exit(0);
	}

	/* parent */
	wait_pid = waitpid(child_pid, &status, 0);
	if(wait_pid < 0)
		error("waitpid");

	if(wait_pid != child_pid)
	{
	 	error("waitpid returned the wrong pid for the child process");
	}
}

void test_sem(void)
{
	int semID;
	struct sembuf sb;
	int err, val;

	semID = chk_error(semget(IPC_PRIVATE, 1, 0666 | IPC_CREAT));

	if(semctl(semID, 0, SETVAL, 0) < 0)
	{
		semctl(semID, 0, IPC_RMID);
		error("semctl"); 
	}

	sb.sem_num = 0;
	sb.sem_op = -1;
	sb.sem_flg = IPC_NOWAIT;

	/* try lock, should return EAGAIN */

	err = semop(semID, &sb, 1);

	if(err != -1 || errno != EAGAIN)	
	{
		semctl(semID, 0, IPC_RMID);
		error("semop");
	}

	//post to semaphore
	sb.sem_op = 1;
	sb.sem_flg = 0;
	if(semop(semID, &sb, 1) < 0)
	{
		semctl(semID, 0, IPC_RMID);
		error("semctl"); 
	}
											
	//check that it posted 
	if((val = chk_error(semctl(semID, 0, GETVAL))) < 0)
	{
		semctl(semID, 0, IPC_RMID);
		error("semctl");
	}
												
	if(val != 1)
	{
		error("semctl");
	}
												
	//pend on the semaphore
	sb.sem_op = 1;
	if(semop(semID, &sb, 1) < 0)
	{
		semctl(semID, 0, IPC_RMID);
		error("semop");
	}

	//destroy the semaphore
	semctl(semID, 0, IPC_RMID);
}

void test_rlimit()
{
	struct rlimit rlp;

	chk_error(getrlimit(RLIMIT_AS, &rlp));
	chk_error(setrlimit(RLIMIT_AS, &rlp));

	chk_error(getrlimit(RLIMIT_CORE, &rlp));
	chk_error(setrlimit(RLIMIT_CORE, &rlp));

	chk_error(getrlimit(RLIMIT_CPU, &rlp));
	chk_error(setrlimit(RLIMIT_CPU, &rlp));

	chk_error(getrlimit(RLIMIT_DATA, &rlp));
	chk_error(setrlimit(RLIMIT_DATA, &rlp));

	chk_error(getrlimit(RLIMIT_FSIZE, &rlp));
	chk_error(setrlimit(RLIMIT_FSIZE, &rlp));

	chk_error(getrlimit(RLIMIT_MEMLOCK, &rlp));
	chk_error(setrlimit(RLIMIT_MEMLOCK, &rlp));

	chk_error(getrlimit(RLIMIT_NOFILE, &rlp));
	chk_error(setrlimit(RLIMIT_NOFILE, &rlp));

	chk_error(getrlimit(RLIMIT_NPROC, &rlp));
	chk_error(setrlimit(RLIMIT_NPROC, &rlp));

	chk_error(getrlimit(RLIMIT_RSS, &rlp));
	chk_error(setrlimit(RLIMIT_RSS, &rlp));

	chk_error(getrlimit(RLIMIT_SBSIZE, &rlp));
	chk_error(setrlimit(RLIMIT_SBSIZE, &rlp));

	chk_error(getrlimit(RLIMIT_STACK, &rlp));
	chk_error(setrlimit(RLIMIT_STACK, &rlp));

	chk_error(getrlimit(RLIMIT_SWAP, &rlp));
	chk_error(setrlimit(RLIMIT_SWAP, &rlp));

	chk_error(getrlimit(RLIMIT_NPTS, &rlp));
	chk_error(setrlimit(RLIMIT_NPTS, &rlp));

	rlim_t old_limit, new_limit;
	
	chk_error(getrlimit(RLIMIT_CPU, &rlp));
	old_limit = rlp.rlim_cur;

	if(old_limit != RLIM_INFINITY)
	{
		new_limit  = old_limit/2;
	}
	else
	{
		new_limit = 10; //just some arbitrary number 
	}
	
	rlp.rlim_cur = new_limit; 

	chk_error(setrlimit(RLIMIT_CPU, &rlp));
	
	//clear entries
	rlp.rlim_cur = 0;
	rlp.rlim_max = 0;

	chk_error(getrlimit(RLIMIT_CPU, &rlp));

	if(rlp.rlim_cur != new_limit)
	{
		printf("bad limit: %d\n", (int)rlp.rlim_cur);
		error("setrlimit");
	}
	
	rlp.rlim_cur = old_limit;

	chk_error(setrlimit(RLIMIT_CPU, &rlp));
}

void test_exec()
{
	pid_t pid;
	int status;

	char bin[32];

	/*
	char arg[32]; 
	#ifndef ARCH
		error("Architecture not defined");
	#elif ARCH==ARCH_X86
		strcpy(arg, "./helpers/x86_exec_test");
		strcpy(bin, "/usr/local/bin/qemu-x86_64"); //needs no emulator
	#elif ARCH==ARCH_MIPS
		strcpy(arg, "./helpers/mips_exec_test");
		strcpy(bin, "/usr/local/bin/qemu-mips64");
	#elif ARCH==ARCH_SPARC
		strcpy(bin, "/usr/local/bin/qemu-sparc64"); 
		strcpy(arg, "./helpers/sparc_exec_test");
	#endif
	*/

	strcpy(bin, "./helpers/x86_exec_test"); 

	char *envp[] = { NULL };
	char *argv[] = { bin, "word", NULL};

	pid = chk_error(fork());

	if(pid == 0)
	{	
		chk_error(execve(bin, argv, envp));
		exit(0);
	}
	else
	{
		chk_error(waitpid(pid, &status,0));
		if(WIFEXITED(status))
		{
			if(WEXITSTATUS(status) != 123)
			{
				error("waitpid status");
			}
		}
		else
		{
			error("execve");
		}
	}

}

void test_priority()
{
	int old_priority, new_priority, my_priority; 
	
	//clear errno since -1 is a valid return value
	errno = 0; 
	old_priority = getpriority(PRIO_PROCESS, 0); 
	if(old_priority == -1 && errno != 0)
	{
		error("getpriority");
	}

	if(old_priority >= 20)
	{
		new_priority = old_priority+1; 
	}
	else
	{
		new_priority = old_priority; 
	}

	chk_error(setpriority(PRIO_PROCESS, 0, new_priority));

	//check that it changed
	errno = 0;
	my_priority = getpriority(PRIO_PROCESS, 0);
	if(my_priority == -1 && errno != 0)
	{
		error("getpriority");
	}

	if(my_priority != new_priority)
	{
		error("setpriority");	
	}

//	chk_error(setpriority(PRIO_PROCESS, 0, old_priority));
}

void test_socket_echo()
{
	char *hostname = "localhost";
	char *service = "7";
	struct addrinfo hints, *res;
	int sock;
	char buf[32];

	//TCP
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	chk_error(getaddrinfo(hostname, service, &hints, &res));

	sock = chk_error(socket(res->ai_family, res->ai_socktype, res->ai_protocol));

	chk_error(connect(sock, res->ai_addr, res->ai_addrlen)); 
		
	chk_error(write(sock, "foo", 4));
	chk_error(read(sock, buf, 4));

	if(strcmp(buf, "foo") != 0)
	{
		error("Echo server didn't return correct value");
	}

	close(sock);

	//now test UDP
	sock = chk_error(socket(AF_INET, SOCK_DGRAM, 0));
	chk_error(sendto(sock, "bar", 4, 0, res->ai_addr, res->ai_addrlen)); 
	chk_error(recvfrom(sock, buf, 4, 0, NULL, NULL)); 

	if(strcmp(buf, "bar") != 0)
	{

			
			error("Echo server didn't return correct value");
	}

	close(sock); 
	freeaddrinfo(res);
}

void test_flock()
{
	int fd;
	int pid;
	int status; 
	char cur_dir[1024];

	/*clean up, just in case */
	unlink(TESTPATH "/test");
	rmdir(TESTPATH);

	if(getcwd(cur_dir, sizeof(cur_dir)) == NULL)
			error("getcwd");

	chk_error(mkdir(TESTPATH, 0755));
	chk_error(chdir(TESTPATH));


	fd = chk_error(open("test", (O_RDWR | O_CREAT), 0644 ));  

	chk_error(flock(fd, LOCK_EX));
	
	pid = chk_error(fork());

	if(pid == 0)
	{
		int child_fd = -1; 
		int err;
		
		child_fd = chk_error(open("test", O_RDWR, 0));
		err = flock(child_fd, (LOCK_EX | LOCK_NB));

		if(err == -1)
		{
			if(errno != EWOULDBLOCK)
			{
				error("flock");
			}
		}
		else
		{
			error("flock call should have failed with EWOULDBLOCK");
		}

		exit(0);
	}

	chk_error(wait4(pid, &status, 0, NULL));

	if( WIFEXITED(status) && WEXITSTATUS(status) )
	{
		error("wait4");			
	}

	chk_error(flock(fd,  LOCK_UN));

	chk_error(close(fd));
	chk_error(unlink("test"));
	chk_error(chdir(cur_dir));
	chk_error(rmdir(TESTPATH));

}

void test_getsetlogin()
{	
	int pid, status, err, len; 
	char * new_name = NULL;
	char * my_name = NULL;
	char * tmp = NULL;

	pid = chk_error(fork());

	if(pid == 0)
	{
		my_name = getlogin();

		if(my_name == NULL)
		{
			error("getlogin");
			exit(0);
		}

		//store the name so we can restore it 
		len = strlen(my_name);
		tmp = (char *)malloc(len+1);
		strcpy(tmp, my_name); 
		my_name = tmp; 
	
		err = setlogin("newname");

		if(err < 0)
		{	
			free(tmp);

			if(errno == EPERM)
			{
				printf("Unable to test setlogin(), skipping \n");
				exit(0);
			}

			error("setlogin");
		}

		new_name = getlogin();

		if(new_name == NULL)
		{
			error("getlogin");
		}
		
		if(strcmp("newname", new_name) != 0)
		{
			error("setlogin");
		}

		//restore original name
		if(setlogin(my_name) < 0)
		{
			free(tmp);
			error("setlogin");
		}

		free(tmp); 
		exit(0);
	}
	
	chk_error(wait4(pid, &status, 0, NULL));

	if(WIFEXITED(status) && WEXITSTATUS(status) != 0)
	{
		error("child process exited with error");
	}
}

void test_msg_queue()
{	
	int queueID = -1; 
	struct msqid_ds stat_buf; 
	
	struct my_msgbuf {
		long mtype;
		char mtext[10];
	} buf; 
	

	/* make a msg queue */

	queueID = msgget(IPC_PRIVATE, (IPC_CREAT | IPC_EXCL | IPC_R | IPC_W));

	if(queueID < -1)
	{	
		error("msgget");
	}

	/* check the stats */
	if(msgctl(queueID, IPC_STAT, &stat_buf) < 0)
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgctl");
	}

	if(stat_buf.msg_perm.cuid != geteuid())
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgctl IPC_STAT creator uid");
	}
	
	if((stat_buf.msg_perm.mode & (IPC_R | IPC_W)) == 0)
	{
		msgctl(queueID, IPC_RMID, 0); 
		error("msgctl IPC_STAT mode"); 
	}

	/* send a message */
	strcpy(buf.mtext, "foo");
	buf.mtype = 1; 
	if(msgsnd(queueID, &buf, sizeof(buf.mtext), 0) < 0)
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgsnd");
	}

	/* there should now be 1 msg in the queue */
	if(msgctl(queueID, IPC_STAT, &stat_buf) < 0)
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgctl");
	}

	if(stat_buf.msg_qnum != 1)
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgsnd");
	}

	/* receive the msg */
	bzero((void *) &buf, sizeof(buf));

	if(msgrcv(queueID, &buf, sizeof(buf.mtext), 0, 0) < 0)
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgrcv"); 
	}

	if(strcmp( &buf.mtext[0], "foo") != 0)
	{
        msgctl(queueID, IPC_RMID, NULL);
		error("msgrcv");
	}
	
    /* there should now be 1 msg in the queue */
	if(msgctl(queueID, IPC_STAT, &stat_buf) < 0)
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgctl");
	}

	if(stat_buf.msg_qnum != 0)
	{
		msgctl(queueID, IPC_RMID, NULL);
		error("msgrcv didn't remove msg from queue");
	}
	
	chk_error(msgctl(queueID, IPC_RMID, NULL));

}

int main(int argc, char **argv)
{ 
	test_file();
	test_fork();
	test_time();
	test_socket_echo();
	test_socket();
	test_signal();
	test_shm();
	test_uid();
	test_pipe();  
	test_sem();   
	test_rlimit();  
	test_exec();
	test_priority();
	test_flock();
	test_getsetlogin();
	test_msg_queue();


    return 0;
}
