#include <stdio.h>
#include <unistd.h>

void win(void) {
    char buf[256] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            printf("%s", buf);
        }
        fclose(f);
    } else {
        puts("flag.txt not found (this is an offline eval fixture)");
    }
}

void vuln(void) {
    char buf[64];
    puts("Say something:");
    /* Deliberately unbounded: classic stack buffer overflow, no gets()
     * needed (gets() was dropped from modern glibc). */
    read(0, buf, 512);
    printf("You said: %s\n", buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    puts("Bye!");
    return 0;
}
