#include <stdio.h>
#include <stdlib.h>
struct test_t{
    const char* name;
    int flags;
};

int main(){
    struct test_t *test = (struct test_t *)malloc(sizeof(struct test_t));
    unsigned long kddr=ffffffffbb55c500;
    test->name="shubh";
    
    test->flags=8;
    struct file_system_type fst = (struct file_system_type *)kddr;
    printf("%s\n", );
    return 0;
}