from jinja2 import Template
def safe():
    user_input = input("Enter name: ")
    t = Template("Hello {{ name }}")  # SAFE: template is constant
    return t.render(name=user_input)
