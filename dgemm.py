import numpy as np
import time

A = np.random.rand(10000,10000)
B = np.random.rand(10000,10000)

start_time = time.perf_counter_ns()
C = np.dot(A,B)
end_time = time.perf_counter_ns()

elapsed_time_ns = (end_time - start_time)/1E9
print(f"Time taken for np.dot: {elapsed_time_ns} s")