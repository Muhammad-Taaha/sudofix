from jinja2 import Template

def vulnerable():
    user_template = input("Enter template: ")
    # DANGEROUS: user-controlled template
    t = Template(user_template)
    return t.render(name="test")
