#!/usr/bin/env python3

##
## List Comprehension
##
## 
## new_list = [expression for member in iterable if condition]
##

list = [i for i in range(10)]

squares_list = [item**2 for item in list]

squares_divisible_by_3_list = [item for item in squares_list if not item%3]
## OR
## squares_divisible_by_3_list = [item for item in [item**2 for item in list] if not item % 3]

square_only_even_divisible_by_3_list = \
    [item**2 if not item%2 else item for item in list if not item%3]

print(list)
print(squares_list)
print(squares_divisible_by_3_list)
print(square_only_even_divisible_by_3_list)

