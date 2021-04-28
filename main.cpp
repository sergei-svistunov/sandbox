#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <regex>
#include <cstdlib>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <mntent.h>

#include <boost/filesystem.hpp>
#include <libcgroup.h>

#define STACK_SIZE (1024 * 1024)
#define NOBODY_UID 65534

namespace fs = boost::filesystem;
namespace bs = boost::system;

struct exe_opts {
    const fs::path &bin_path;
    const std::vector<char *> &args;
    const std::vector<char *> &env;
};

static pid_t pid;
static fs::path sandbox = {};
static cgroup *sandbox_cgroup = nullptr;

void fatal(const std::string &message) {
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}

void fatal_errno(const std::string &message) {
    std::cerr << message << ": " << strerror(errno) << std::endl;
    exit(EXIT_FAILURE);
}

void fatal_cgroup(const std::string &message) {
    std::cerr << message << ": " << cgroup_strerror(cgroup_get_last_errno()) << std::endl;
    exit(EXIT_FAILURE);
}

void path_pids(std::vector<int> &res) {
    if (!fs::exists(sandbox)) { ;
        return;
    }

    std::array<char, 256> buffer{};

    std::string out_buf;
    auto lsof_cmd = std::string("/usr/bin/lsof -n -w -Fp +d ") + sandbox.string();
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(lsof_cmd.c_str(), "r"), pclose);
    if (!pipe) {
        fatal("cannot get path pids");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        out_buf += buffer.data();
    }

    std::regex e(R"(p([\d]+))");
    std::smatch m;

    while (std::regex_search(out_buf, m, e)) {
        if (m.length() < 2)
            continue;

        res.push_back(std::strtol(m[1].first.base(), nullptr, 10));

        out_buf = m.suffix().str();
    }
}

void kill_all_sandbox_processes() {
    // Kill all processes that use the path
    std::vector<int> pids;
    path_pids(pids);
    for (auto p: pids) {
        std::cerr << "Kill pid " << p << std::endl;
        kill(p, SIGKILL);
    }

    for (auto p: pids)
        waitpid(p, nullptr, 0);
}

void remove_sandbox_path() {
    if (!fs::exists(sandbox)) { ;
        return;
    }

    // Remove path
    auto mounts_f = setmntent("/proc/mounts", "r");
    while (auto mounts = getmntent(mounts_f)) {
        if (std::string(mounts->mnt_dir).find(sandbox.string()) != 0)
            continue;

        int i = 0;
        while (++i) {
            if (umount2(mounts->mnt_dir, MNT_FORCE)) {
                if (errno == EBUSY) {
                    if (i % 50 == 0)
                        std::cerr << "cannot umount: busy, retry" << std::endl;

                    sleep(0);
                    continue;
                }
                fatal_errno(std::string("cannot umount ") + mounts->mnt_dir);
            }
            break;
        }
    }
    endmntent(mounts_f);

    bs::error_code ec;
    fs::remove_all(sandbox, ec);
    if (ec.value() != bs::errc::success)
        fatal("cannot remove sandbox: " + ec.message());
}

void clean() {
    // Remove cgroups
    if (sandbox_cgroup != nullptr) {
        if (cgroup_delete_cgroup(sandbox_cgroup, 0))
            fatal_cgroup("cannot delete cgroup");

        cgroup_free(&sandbox_cgroup);
    }

    remove_sandbox_path();
}

void init_dirs() {
    kill_all_sandbox_processes();
    remove_sandbox_path();

    std::array<std::string, 5> dirs = {"dev", "etc", "proc", "root", "tmp"};

    bs::error_code ec;
    for (auto &dir:dirs) {
        fs::create_directories(sandbox / dir, ec);
        if (ec.value() != bs::errc::success)
            fatal("cannot create system dir: " + ec.message());
    }

    if (chmod((sandbox / "tmp").c_str(), 0777))
        fatal_errno("cannot set mode 777 for /tmp");
}

void libs_deps(fs::path &bin, std::vector<std::string> &res) {
    std::array<char, 256> buffer{};

    std::string out_buf;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(
            (std::string("/usr/bin/ldd ") + bin.string()).c_str(), "r"), pclose);
    if (!pipe) {
        fatal("cannot get libraries dependencies");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        out_buf += buffer.data();
    }

    std::regex e(R"((?:.+?\s+=>)?\s+(/.+?)\s+\(.+?\))");
    std::smatch m;

    while (std::regex_search(out_buf, m, e)) {
        if (m.length() < 2)
            continue;
        res.push_back(m[1]);
        out_buf = m.suffix().str();
    }
}

void create_hardlink(const fs::path &src, const fs::path &dst) {
    bs::error_code ec;

    fs::path real_path = src;
    if (fs::is_symlink(src)) {
        auto target = fs::read_symlink(src, ec);
        if (ec.value() != bs::errc::success)
            fatal("cannot read symlink shared link: " + ec.message());

        if (target.has_root_path())
            real_path = target;
        else
            real_path = fs::path(src).parent_path() / target;
    }

    fs::create_directories(dst.parent_path(), ec);
    if (ec.value() != bs::errc::success)
        fatal("cannot create directory for hard link: " + ec.message());

    fs::create_hard_link(real_path, dst, ec);
    if (ec != bs::errc::success) {
        if (ec == bs::errc::file_exists)
            return;

        if (ec == bs::errc::cross_device_link) {
            fs::copy_file(real_path, dst, ec);
            if (ec != bs::errc::success) {
                fatal("cannot copy cross-device file: " + ec.message());
            }
            return;
        }

        fatal("cannot create hardlink: " + ec.message());
    }
}

void add_file(const fs::path &src, const fs::path &dst, bool with_deps) {
    auto sbox_path = sandbox / dst;

    create_hardlink(src, sbox_path);

    if (with_deps) {
        std::vector<std::string> libs;
        libs_deps(sbox_path, libs);

        for (auto &l:libs) {
            create_hardlink(l, sandbox / l);
        }
    }
}

void mount_dir(const fs::path &src, const fs::path &dst) {
    auto sbox_path = sandbox / dst;

    bs::error_code ec;
    fs::create_directories(sbox_path, ec);
    if (ec.value() != bs::errc::success)
        fatal("cannot create target mount directory: " + ec.message());

    if (mount(src.c_str(), sbox_path.c_str(), "", MS_BIND, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount dir " + src.string());
}

cgroup *create_cgroup(const std::string &name, const std::string &cpu_set, uint64_t mem_limit) {
    if (cgroup_init())
        fatal_cgroup("cannot init cgroup");

    auto cgroup = cgroup_new_cgroup(name.c_str());

    if (!cpu_set.empty()) {
        auto cpuset_ctrl = cgroup_add_controller(cgroup, "cpuset");
        if (cgroup_set_value_string(cpuset_ctrl, "cpuset.cpus", cpu_set.c_str()))
            fatal_cgroup("cannot set cpuset.cpus");

        if (cgroup_set_value_string(cpuset_ctrl, "cpuset.cpus", cpu_set.c_str()))
            fatal_cgroup("cannot set cpuset.cpus");

        if (cgroup_set_value_string(cpuset_ctrl, "cpuset.mems", "0"))
            fatal_cgroup("cannot set cpuset.mems");
    }

    if (mem_limit) {
        auto mem_ctrl = cgroup_add_controller(cgroup, "memory");

        if (cgroup_set_value_uint64(mem_ctrl, "memory.limit_in_bytes", mem_limit))
            fatal_cgroup("cannot set memory limit");
    }

    cgroup_add_controller(cgroup, "cpuacct");
    cgroup_add_controller(cgroup, "blkio");

    if (cgroup_create_cgroup(cgroup, 0))
        fatal_cgroup("cannot create cgroup");

    return cgroup;
}

static int _execute(void *arg) {
    auto *opts = static_cast<exe_opts *>(arg);

    if (chroot(sandbox.c_str()))
        fatal_errno("cannot chroot");

    if (mount("udev", "/dev", "devtmpfs", 0, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount /dev");

    if (mount("proc", "/proc", "proc", 0, nullptr))
        if (errno != EBUSY)
            fatal_errno("cannot mount /proc");

    if (chdir("/root"))
        fatal_errno("cannot chdir");

    if (setgid(NOBODY_UID))
        fatal_errno("cannot set GID");

    if (setuid(NOBODY_UID))
        fatal_errno("cannot set UID");

    execve(opts->bin_path.c_str(), opts->args.data(), opts->env.data());
    fatal("cannot run file: " + std::string(strerror(errno)));

    return EXIT_SUCCESS;
}

void save_usage_stat(const std::string &filename, const std::string &cgroup_name) {
    fs::ofstream out(filename);
    if (!out.is_open())
        fatal_errno("cannot create file for usage statistic");

    fs::ifstream cpu_usage_in(fs::path("/sys/fs/cgroup/cpuacct") / cgroup_name / "cpuacct.usage_all");
    if (cpu_usage_in.is_open()) {
        std::string header;
        cpu_usage_in >> header >> header >> header;
        uint64_t total_user = 0;
        uint64_t total_system = 0;
        while (cpu_usage_in) {
            uint64_t cpu_id, user, system;
            cpu_usage_in >> cpu_id >> user >> system;
            total_user += user;
            total_system += system;
        }

        out << "cpu_user\t" << total_user << "\n";
        out << "cpu_system\t" << total_system << "\n";
    }

    fs::ifstream memory_usage_in(fs::path("/sys/fs/cgroup/memory") / cgroup_name / "memory.usage_in_bytes");
    if (memory_usage_in.is_open()) {
        uint64_t bytes = 0;
        memory_usage_in >> bytes;
        out << "memory\t" << bytes << "\n";
    }
}

int execute(const fs::path &bin, const std::vector<char *> &args, const std::vector<char *> &env, const int flags,
            const std::string &cgroup_name, const std::string &cpu_set, const uint64_t mem_limit,
            const std::string &usage_stat_file) {

    if (mem_limit && cgroup_name.empty())
        fatal("cannot set memory limit without cgroup name");

    exe_opts opts{bin, args, env};

    if (!cgroup_name.empty()) {
        sandbox_cgroup = create_cgroup(cgroup_name, cpu_set, mem_limit);
        if (cgroup_attach_task(sandbox_cgroup))
            fatal_cgroup("cannot attach process to cgroup");
    }

    char *stack, *stackTop;
    stack = static_cast<char *>(malloc(STACK_SIZE));
    if (stack == nullptr)
        fatal("cannot allocate stack");

    stackTop = stack + STACK_SIZE;

    pid = clone(_execute, stackTop, flags, &opts);
    if (pid == -1)
        fatal("cannot clone");

    int wstatus;
    waitpid(pid, &wstatus, 0);

    if (!usage_stat_file.empty())
        save_usage_stat(usage_stat_file, cgroup_name);

    clean();

    return WEXITSTATUS(wstatus);
}

void print_usage() {
    std::cout << R"(Usage:
    sandbox <sandbox path> [args] -- <cmd to execute> [cmd args]
args:
    --add_file <src host path> <dst sandbox path>
        Copy a file from a host system to a sandbox

    --add_elf_file <src host path> <dst sandbox path>
        Copy an ELF file from a host system to a sandbox with needed libraries

    --mount_dir <src host path> <dst sandbox path>
        Mount a directory from a host system to a sandbox

    --env <value>
        Environ variables

    --no_new_net
        Do not isolate network

    --cgroup <name>
        Run a process in a cgroup

    --cpuset list
        Specifies the CPUs that are permitted to access

    --mem_limit 0
        Limit memory for a process

    --save_usage_stat <filename>
        Save usage statistic to file after exit
)" << std::endl;

    exit(EXIT_FAILURE);
}

void signalHandler(int signum) {
    kill(pid, SIGINT);
    waitpid(pid, nullptr, 0);

    clean();

    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    if (getuid() != 0 && geteuid() != 0)
        fatal("required root privileges");

    if (setreuid(0, 0))
        fatal_errno("cannot set reuid");

    if (argc < 2 || strncmp(argv[1], "--", 2) == 0)
        print_usage();

    sandbox = argv[1];

    init_dirs();

    // link sandbox manager process with sandbox path
    if (!fopen(sandbox.c_str(), "r"))
        fatal_errno("cannot open sandbox path");

    fs::path cmd;
    std::string cgroup, cpu_set, usage_stat_file;
    uint64_t mem_limit = 0;
    std::vector<char *> cmd_args = {nullptr}; // reserved for cmd path
    std::vector<char *> cmd_env;
    int ignored_flags = 0;

    auto i = 2;
    while (i < argc) {
        if (strcmp(argv[i], "--") == 0) {
            if (i + 1 > argc)
                print_usage();
            cmd = argv[i + 1];

            for (i = i + 2; i < argc; i++)
                cmd_args.emplace_back(argv[i]);

            break;
        } else if (strcmp(argv[i], "--add_file") == 0 || strcmp(argv[i], "--add_elf_file") == 0) {
            if (i + 3 > argc || strncmp(argv[i + 1], "--", 2) == 0 || strncmp(argv[i + 2], "--", 2) == 0)
                print_usage();

            add_file(argv[i + 1], argv[i + 2], strcmp(argv[i], "--add_elf_file") == 0);

            i += 3;

        } else if (strcmp(argv[i], "--mount_dir") == 0) {
            if (i + 3 > argc || strncmp(argv[i + 1], "--", 2) == 0 || strncmp(argv[i + 2], "--", 2) == 0)
                print_usage();

            mount_dir(argv[i + 1], argv[i + 2]);

            i += 3;

        } else if (strcmp(argv[i], "--env") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cmd_env.push_back(argv[i + 1]);

            i += 2;

        } else if (strcmp(argv[i], "--no_new_net") == 0) {
            ignored_flags |= CLONE_NEWNET;

            i++;

        } else if (strcmp(argv[i], "--cgroup") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cgroup = argv[i + 1];

            i += 2;

        } else if (strcmp(argv[i], "--cpuset") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            cpu_set = argv[i + 1];

            i += 2;

        } else if (strcmp(argv[i], "--mem_limit") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            mem_limit = std::strtoll(argv[i + 1], nullptr, 10);

            i += 2;

        } else if (strcmp(argv[i], "--save_usage_stat") == 0) {
            if (i + 2 > argc || strncmp(argv[i + 1], "--", 2) == 0)
                print_usage();

            usage_stat_file = argv[i + 1];

            i += 2;

        } else {
            print_usage();
        }
    }

    int flags = CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWCGROUP | SIGCHLD;
    if ((ignored_flags & CLONE_NEWNET) == 0)
        flags |= CLONE_NEWNET;

    cmd_args[0] = const_cast<char *>(cmd.c_str());
    cmd_args.push_back(nullptr);
    cmd_env.push_back(nullptr);

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    return execute(cmd, cmd_args, cmd_env, flags, cgroup, cpu_set, mem_limit, usage_stat_file);
}
