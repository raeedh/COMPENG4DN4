#!/usr/bin/env python3

from person import *

p_1 = Person("John", "Smith")
p_2 = Person(first_name="Jane", last_name="Smith")

# print(locals())
# print()

print(p_1)
print(p_2)
print()

print(type(p_1))
print(type(p_2))
print()

print(vars(p_1))
print(vars(p_2))
print()

print(p_1.full_name())
print(p_2.full_name())
print()





