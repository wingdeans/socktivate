## State
```mermaid
stateDiagram-v2
    [*] --> Stopped
    Stopped --> NeedSeccompFd: socket
    NeedSeccompFd --> [*]: pidfd
    NeedSeccompFd --> NeedSeccompNotify: unix socket
    NeedSeccompNotify --> Started: seccomp
    NeedSeccompNotify --> [*]: pidfd
    Started --> Idle: timer
    Idle --> Started: socket
    Idle --> [*]: timer
    Started --> [*]: pidfd
```

## Config
```
# comment lines start with #
8000 /usr/bin/some_command some_args
# continued commands start with whitespace
     --some_more_args

# empty lines also continue commands
     --some_even_more_args
```
