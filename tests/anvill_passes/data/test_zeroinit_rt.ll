; ModuleID = 'test_zeroinit_rt.ll'
source_filename = "lifted_code"
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu-elf"

@var_601044_i = global i32 0
@var_6011b0_l = global i64 0
@__anvill_reg_RBP = internal local_unnamed_addr global i64 0
@__anvill_sp = internal global i8 0
@__anvill_ra = internal global i8 0
@llvm.compiler.used = appending global [5 x ptr] [ptr @sub_4003b4__All_Svl_B_0, ptr @main, ptr @__libc_start_main, ptr @var_601044_i, ptr @var_6011b0_l], section "llvm.metadata"
@__anvill_stack_minus_12 = global i8 0
@__anvill_stack_minus_11 = global i8 0
@__anvill_stack_minus_10 = global i8 0
@__anvill_stack_minus_9 = global i8 0
@__anvill_stack_minus_8 = global i8 0
@__anvill_stack_minus_7 = global i8 0
@__anvill_stack_minus_6 = global i8 0
@__anvill_stack_minus_5 = global i8 0
@__anvill_stack_minus_4 = global i8 0
@__anvill_stack_minus_3 = global i8 0
@__anvill_stack_minus_2 = global i8 0
@__anvill_stack_minus_1 = global i8 0
@__anvill_stack_0 = global i8 0
@__anvill_stack_plus_1 = global i8 0
@__anvill_stack_plus_2 = global i8 0
@__anvill_stack_plus_3 = global i8 0
@__anvill_stack_plus_4 = global i8 0
@__anvill_stack_plus_5 = global i8 0
@__anvill_stack_plus_6 = global i8 0
@__anvill_stack_plus_7 = global i8 0

; Function Attrs: noinline
declare i64 @sub_4003b4__All_Svl_B_0(i64, i64, ptr) #0

; Function Attrs: noinline
define i32 @main(i32 %0, ptr %1, ptr %2) #0 {
  %4 = load i32, ptr @var_601044_i, align 4
  %5 = icmp eq i32 %4, 0
  br i1 %5, label %7, label %6

6:                                                ; preds = %3
  br label %8

7:                                                ; preds = %3
  br label %8

8:                                                ; preds = %7, %6
  %storemerge = phi i32 [ 3, %6 ], [ 1, %7 ]
  store i32 %storemerge, ptr @var_601044_i, align 4
  %9 = load i64, ptr @var_6011b0_l, align 8
  %10 = icmp eq i64 %9, 0
  br i1 %10, label %12, label %11

11:                                               ; preds = %8
  br label %13

12:                                               ; preds = %8
  br label %13

13:                                               ; preds = %12, %11
  %14 = phi i32 [ 4, %11 ], [ 2, %12 ]
  %storemerge1 = phi i64 [ 4, %11 ], [ 2, %12 ]
  store i64 %storemerge1, ptr @var_6011b0_l, align 8
  %15 = load i32, ptr @var_601044_i, align 4
  %16 = add i32 %15, %14
  ret i32 %16
}

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_64(ptr, i64, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local ptr @__remill_write_memory_32(ptr, i64, i32) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i32 @__remill_read_memory_32(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone readnone
declare dso_local i64 @__remill_read_memory_64(ptr, i64) local_unnamed_addr #1

; Function Attrs: noduplicate noinline nounwind optnone
declare dso_local ptr @__remill_function_return(ptr nonnull align 1, i64, ptr) local_unnamed_addr #2

; Function Attrs: noinline
declare x86_64_sysvcc i32 @__libc_start_main(ptr, i32, ptr, ptr, ptr, ptr, ptr) #0

attributes #0 = { noinline }
attributes #1 = { noduplicate noinline nounwind optnone readnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="none" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #2 = { noduplicate noinline nounwind optnone "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-builtins" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
