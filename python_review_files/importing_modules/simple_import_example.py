#!/usr/bin/env python3

# Illustration of basic module importing with common and external
# namespace.

# Try both True and False:
COMMON_NAMESPACE = True
# COMMON_NAMESPACE = False

if COMMON_NAMESPACE:

    from math import *
    ## OR
    ## from math import cos, pi

    angle = 2*pi
    print("angle = ", angle, "cos(angle) = ", cos(angle))

else:
    
    import math

    angle = 2*math.pi
    print("angle = ", angle, "cos(angle) = ", math.cos(angle))    


    


    
