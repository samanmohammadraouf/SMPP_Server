# SMPP_Server
در این پروژه قصد داریم یک سرور را با استفاده از یک GSM Modem قادر سازیم تا بتواند پیامک sms با استفاده از فرمت smpp protocl  ارسال و دریافت کند . محتوای این پیامک ها مربوط به سامانه ی حضور و غیاب کارمندان می باشد . بدین شکل که کاربر از طریق برنامه گوشی مربوط به این سامانه ، پیام ورود یا خروج خود به همراه ساعت آن را برای سرور ارسال می نماید . در سمت سرور ، حضور و غیاب کارمندان به همراه ساعت ورود یا خروج شان ثبت می گردد . هم چنین پروتکل و قواعد تعیین شده برای این سامانه امنیت را از نظر رمزگذاری و یکپارچگی و احراز هویت تامین می کند که در ادامه شیوه تعیین و پیاده سازی هر یک از بخش های اشاره شده با جزئیات مربوطه آورده شده است . 
# GSM Modem 
برای قادر ساختن سرور به دریافت و ارسال پیامک باید آن را به یک GSM Modem متصل کنیم و از طریق پروتکل smpp  با آن ارتباط برقرار کنیم .  GSM Modem یک نوع از modem برای شبکه های موبایل می باشد که sim card  درش قرار می گیرد و بدین طریق می تواند برای تماس صوتی و یا ارسال متن مورد استقبال قرار بگیرد . یک نوع از GSM Modem  را در شکل زیر می توانید مشاهده کنید. 

![Alt text for the image](GSM-Modems.webp)
اما برای رفع نیاز راه اندازی سرور می توان از گوشی های امروزی نیز به عنوان GSM Modem  برای استفاده ی سرور استفاده کرد . به عبارتی ما گوشی را به عنوان یک GSM Modem  با پروتکل SMPP در نظر می گیریم . برای این کار نیاز است تا گوشی خود را به یک smpp gateway برای سرور تبدیل کنیم . برای این کار از برنامه های شبیه سازی گوشی به Smpp Gateway می توان استفاده کرد که در این پروژه از برنامه Ozeki Smpp Sms Gateway Lite  استفاده شده است . 
![Alt text for the image](photo_2023-07-04_20-20-42.jpg)
همان طور که در این تصویر مربوط به برنامه می توانید مشاهده کنید ، گوشی با استفاده از رمز عبور و نام کاربری قابل اتصال می باشد تا سرور بتواند به عنوان کاربر از آن استفاده کند و پیامک ارسال و دریافت کند . حال با جزئیات دقیق تر به پیاده سازی این اتصال می پردازیم .
# SMPP Gateway Connection 
برای متصل شدن به این GSM Modem  تحت پروتکل smpp  در سمت سرور ، ابتد باید از libaray موجود برای smpp  موارد لازم را import  کنیم 
```
import smpplib.client
import smpplib.gsm
import smpplib.consts
```
با تعریف کلاسی با عنوان SMPP_Message_handler ، یک تابع اولیه در آن برای اتصال تعریف می کنیم . که به شکل زیر است . در این تابع ابتدا با مشخصات داده شده به عنوان ورودی به آن ip , port اتصال برقرار می کنیم و سپس با استفاده از username , password  اتصال را می شناسانیم تا برقرار بماند و reject  نشود . سپس منتظر دریافت پیامک از سوی کاربران ( پیام ورود یا خروج ) می مانیم . در نهایت نیز اتصال را قطع می کنیم . لازم به ذکر است که در تابع receive_sms جزئیات بسیاری وجود دارد که در ادامه بدان می پردازیم و تنها کار آن دریافت پیام و نمایش آن نیست . 
```
class SMPP_Message_handler():
    def __init__(self):
        self.db = AttendanceDB()
....
....
....

    def send_and_receive_sms(self,host, port, username, password, src_addr):
        with smpplib.client.Client(host, port) as client:
            client.connect()
            client.bind_transceiver(system_id=username, password=password)
            self.receive_sms(client)
            client.unbind()
            client.disconnect()



smpp_handler = SMPP_Message_handler()
host = '192.168.1.143'
port = 9500
username = "smppuser"
password = "aVbpZzpt"
src_addr = '9102211824'
smpp_handler.send_and_receive_sms(host, port, username, password, src_addr)
```
حال که شیوه برقراری ارتباط را مشاهده کردیم ، قبل از ادامه بررسی کد پروتکل برنامه خود برای ارسال و دریافت پیامک و شیوه امنیت آن را توضیح می دهیم .
# Attendance SMPP Protocol 
شیوه کلی ارتباط بدین صورت است که ابتدا کاربر یک پیام حاوی ورود یا خروج همراه ساعت آن به سمت سرور می فرستد . این پیام بعد از رمز شدن توسط کلید داخلی برنامه ( که کانال امنی محسوب می شود ) توسط برنامه به سمت سرور فرستاده می شود . سرور بعد از دریافت آن ، آن را رمزگشایی می کند و محتوای آن را ذخیره می کند . سپس به عنوان ack  برای برنامه گوشی ( و کاربر ) همان پیام را ابتدا hash  می کند و سپس عبارتی با مقدار AFTSTC بدان اضافه می کند و کل این محتوا را رمز می کند و برای گوشی می فرستد . 
علت hash کردن محتوای پیام این است که اگر در وسط راه پیام تغییری کرده باشد و مرد میانی دخالتی کرده باشد ، گوشی با دریافت ack  و بررسی برابر بودن hash  پیام اولیه خودش و hash  دریافت شده متوجه این دخالت می شود و بنابراین دوباره پیام خود را به سمت سرور ارسال می کند . بدین شیوه اطمینان حاصل می کند که محتوای اصلی پیام تغییری نکرده باشد . هم چنین با استفاده از رمز کردن همه پیام های بین دو طرف ، امکان خواندن پیام ها توسط مرد میانی ( و نه تغییر آن ) را نیز از کاربر می گیریم . در تصویر زیر می توانید کل فرایند را مشاهده کنید .
![Alt text for the image](Capture3.JPG)
![Alt text for the image](photo_2023-07-04_20-20-42.jpg)
