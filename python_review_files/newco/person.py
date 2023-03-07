
"""An example module for creating Person objects.

"""

class Person:

    def __init__(self, first_name, last_name):
        """
        Create a new person object by calling it with the new person's
        first and last name.

        Example: new_person = Person(first_name="John", last_name="Smith").

        """

        self.first_name = first_name
        self.last_name = last_name

    
    def full_name(self):
        """Return a string with the person's full name."""
        
        return self.first_name + " " + self.last_name


    
