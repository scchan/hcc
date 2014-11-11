// RUN: %amp_device -D__GPU__ %s -m32 -emit-llvm -c -S -O2 -o %t.ll 2>&1 | %FileCheck --strict-whitespace %s

//////////////////////////////////////////////////////////////////////////////////
// Do not delete or add any line; it is referred to by absolute line number in the
// FileCheck lines below
//////////////////////////////////////////////////////////////////////////////////
#include <amp.h>

int f1() restrict(cpu) {return 1;} 
int f2() restrict(amp,auto) {
  return f1();
}
// CHECK: diagnose_before_perform_inferring_CPU.cpp:[[@LINE-2]]:10: error: call from AMP-restricted function to CPU-restricted function
// CHECK-NEXT: return f1();
// CHECK-NEXT:        ^
int main(void)
{
  f2();
  return 0;
}

