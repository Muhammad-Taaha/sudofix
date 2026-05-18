from jinja2 import Template
def vulnerable():
    user_template = input("Enter template: ")
    t = Template(user_template)  # DANGEROUS
    return t.render(name="test")
