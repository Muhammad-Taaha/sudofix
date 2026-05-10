import traceback
try:
    1/0
except:
    traceback.print_exc()  # DANGEROUS
