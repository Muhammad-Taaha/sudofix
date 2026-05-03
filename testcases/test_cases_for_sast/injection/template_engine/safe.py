from jinja2 import Template, Environment

def safe():
    user_input = input("Enter name: ")
    # SAFE: template is fixed, only variable is user-controlled
    t = Template("Hello {{ name }}")
    return t.render(name=user_input)
