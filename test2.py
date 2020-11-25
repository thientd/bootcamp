str = "<script>alert(document.cookie)</script>"
str = str.find("1")
print(str)
str = str.replace(")","")
str = str.replace("<","")
str = str.replace(">","")
str = str.replace("`","")
