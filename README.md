# async-smtplib
A smtplib use asyncio base on python smtplib

recommend copy the code for you project!

# examples

```python
# use ipython
smtp = AioSMTP("host")
await smtp.init()  # create connect by asyncio
await smtp.ehlo()
await smtp.login("username", "password")
await smtp.sendmail(
        "from", ["to"],
        "hello async_smtplib"
    )
```
