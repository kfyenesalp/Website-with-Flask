from flask import Flask,render_template,flash,redirect,url_for,session,logging,request
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys
import random

app = Flask(__name__)
app.secret_key = "proje"

app.config["MYSQL_HOST"] = "127.0.0.1"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "proje"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:  
            return f(*args, **kwargs)
        else:
            flash("Bu işlemi gerçekleştirmek için giriş yapmalısınız.","danger")
            return redirect(url_for("login"))    
    return decorated_function

def admin_login_required(f):    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session["logged_in"]:
            if session["admin_logged_in"]: 
                return f(*args, **kwargs)
            else:
                flash("Böyle bir işlemi yapmaya yetkin yok.","danger")
                return redirect(url_for("index"))
        else:
            flash("Önce siteye giriş yapmalısın.","danger")
            return redirect(url_for("index"))    
    return decorated_function

@app.route("/")
def index():

    cursor = mysql.connection.cursor()

    query = "Select username, name From users where username = %s"

    cursor.execute(query,("{}".format(session["username"]),))

    username,name = cursor.fetchone()

    return render_template("index.html", username = username, name = name)

@app.route("/register/", methods = ["GET","POST"])
def register():
    
    form = RegisterForm(request.form)

    if request.method == "GET":
        
        return render_template("register.html",form = form)
    
    else:
        
        name = form.name.data
        age = form.age.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(form.password.data)

        session["entered_name"] = name
        session["age"] = age
        session["email"] = email
        session["username"] = username
        session["password"] = password
      
        mesaj = MIMEMultipart()

        mesaj["FROM"] = "dogrulamakoduu29@gmail.com"

        mesaj["TO"] = "{}".format(email)

        mesaj["Subject"] = "Doğrulama Kodu"

        session["correct_code"] = random.randint(10000,99999)

        yazı = "Sayın {} , Doğrulama Kodunuz : {}".format(name,session["correct_code"])

        mesaj.gövdesi = MIMEText(yazı,"plain")

        mesaj.attach(mesaj.gövdesi)

        mail = smtplib.SMTP("smtp.gmail.com", 587)

        mail.ehlo()

        mail.starttls()

        mail.login("-","-")

        mail.sendmail(mesaj["From"],mesaj["To"],mesaj.as_string())

        mail.close()
 
        return redirect(url_for("correct_code"))

@app.route("/correctcode", methods = ["GET","POST"])
def correct_code():
    
    form = CorrectCode(request.form)

    if request.method == "GET":
        
        return render_template("correctcode.html",form = form)
    
    else:

        if int(session["correct_code"]) == int(form.correctcode.data):

            cursor = mysql.connection.cursor()

            sorgu = "Insert into users(name,age,email,username,password) VALUES(%s,%s,%s,%s,%s)"

            cursor.execute(sorgu,(session["entered_name"],session["age"],session["email"],session["username"],session["password"]))

            mysql.connection.commit()

            cursor.close()

            session.clear()

            flash("Kaydınız başarıyla tamamlandı.","success")

            return redirect(url_for("index"))    

        else:

            flash("Doğrulama kodunuz hatalı. Lütfen tekrar kayıt olmayı deneyin.","danger")

            return redirect(url_for("register"))       

@app.route("/login", methods = ["GET","POST"])
def login():
    
    form = LoginForm(request.form)

    if request.method == "GET":
        
        return render_template("login.html", form = form)
    
    else:
        
        username = form.username.data
        password = form.password.data

        cursor = mysql.connection.cursor()

        sorgu = "Select * From users where username = %s"

        result = cursor.execute(sorgu,(username,))

        if result > 0:
            
            data = cursor.fetchone()

            real_password = data["password"]

            name = data["name"]

            if sha256_crypt.verify(password,real_password):

                flash("Başarıyla Giriş Yapıldı.","success")
                
                session["logged_in"] = True

                if username == "admin":
                    session["admin_logged_in"] = True

                session["username"] = username

                session["name"] = name
        
                return redirect(url_for("index"))
            
            else:
            
                flash("Kullanıcı adı veya şifreniz hatalı. Lütfen tekrar deneyiniz.","danger")

                return render_template("login.html",form = form)
        else:
            
            flash("Kullanıcı adı veya şifreniz hatalı. Lütfen tekrar deneyiniz.","danger")

            return render_template("login.html",form = form)

@app.route("/forgotmypassword", methods = ["GET","POST"])
def forgotmypassword():
    
    form = ForgotMyPassword(request.form)

    if request.method == "GET":

        return render_template("forgotmypassword.html", form = form)

    else:

        username = form.username.data

        cursor = mysql.connection.cursor()

        sorgu = "Select * From users where username = %s"

        result = cursor.execute(sorgu,(username,))

        if result > 0:
            
            user_data = cursor.fetchone()

            session["f_my_password_username"] = user_data["username"]
            
            session["correct_code"] = random.randint(10000,99999)

            mesaj = MIMEMultipart()

            mesaj["FROM"] = "dogrulamakoduu29@gmail.com"

            mesaj["TO"] = "{}".format(user_data["email"])

            mesaj["Subject"] = "Şifremi Unuttum"

            yazı = "Sayın {} , şifrenizi sıfırlamanız için kullanacağınız doğrulama kodunuz : {}".format(user_data["name"],session["correct_code"])
       
            mesaj.gövdesi = MIMEText(yazı,"plain")

            mesaj.attach(mesaj.gövdesi)

            mail = smtplib.SMTP("smtp.gmail.com", 587)

            mail.ehlo()

            mail.starttls()

            mail.login("-","-")

            mail.sendmail(mesaj["From"],mesaj["To"],mesaj.as_string())

            mail.close()

            return redirect(url_for("forgotmypassword_correctcode"))

        else:
            
            flash("Böyle bir kullanıcı bulunmuyor.","danger")
            
            return redirect(url_for("index"))      

@app.route("/forgotmypassword/correct-code/", methods = ["GET","POST"])
def forgotmypassword_correctcode():

        form = CorrectCode(request.form)

        if request.method == "GET":

            return render_template("fcorrectcode.html", form = form)

        else:

            code = form.correctcode.data

            if int(session["correct_code"]) == int(code):

                return redirect(url_for("newpassword"))
            
            else:

                flash("Doğrulama Kodunuz hatalı. Lütfen tekrar deneyiniz.","danger")

                return redirect(url_for("login"))
            
@app.route("/new-password", methods = ["GET","POST"])
def newpassword():
    
    form = NewPass(request.form)

    if request.method == "GET":

        return render_template("newpassword.html", form = form)

    else:

        new_password = sha256_crypt.encrypt(form.new_password.data)  

        cursor = mysql.connection.cursor()

        sorgu = "Update users set password = %s where username = %s"

        cursor.execute(sorgu,(new_password,session["f_my_password_username"]))

        mysql.connection.commit()

        cursor.close()

        flash("Şifreniz başarıyla güncellendi.","success")

        return redirect(url_for("login"))    

@app.route("/logout")
@login_required
def logout():

    session.clear()

    flash("Çıkış yapıldı.","success")

    return redirect(url_for("index"))           

@app.route("/analysis")
def analysis():
   
    cursor = mysql.connection.cursor()

    sorgu = "Select * From shares"

    cursor.execute(sorgu)

    datas = cursor.fetchall()

    return render_template("analysis.html",datas = datas)

@app.route("/control", methods = ["GET","POST"])
@admin_login_required
def control():

    form = AddAnalysis(request.form)

    if request.method == "GET":

        cursor = mysql.connection.cursor()

        sorgu = "Select * From shares"

        cursor.execute(sorgu)

        datas = cursor.fetchall()

        return render_template("control.html",datas = datas, form = form)
    
    else:
        
        title = form.title.data 
        
        content = form.content.data

        cursor = mysql.connection.cursor()

        sorgu = "Insert into shares(username,title,content) VALUES(%s,%s,%s)"

        cursor.execute(sorgu,("admin",title,content))

        mysql.connection.commit()

        cursor.close()

        flash("İnceleme başarıyla eklendi.","success")

        return redirect(url_for("analysis"))

@app.route("/delete-analysis/<string:id>")
@admin_login_required
def delete_analysis(id):

    cursor = mysql.connection.cursor()

    sorgu = "Select * from shares where id = %s"

    result = cursor.execute(sorgu,(id,))

    if result > 0:
        sorgu2 = "Delete from shares where id = %s"
        cursor.execute(sorgu2,(id))
        mysql.connection.commit()
        cursor.close()
        flash("İnceleme Başarıyla Silindi.","success")
        return redirect(url_for("control"))
    else:
        flash("Böyle bir veri bulunmuyor.","danger")
        return redirect(url_for("control"))

@app.route("/update-analysis/<string:id>", methods = ["GET","POST"])
@admin_login_required
def update_analysis(id):
    
    cursor = mysql.connection.cursor()

    sorgu = "Select * From shares where id = %s"

    cursor.execute(sorgu,(id,))

    data = cursor.fetchone()
   

    if request.method == "GET":

        form = UpdateAnalysis()

        form.title.data = data["title"]

        form.content.data = data["content"]

        return render_template("control.html", form = form)

    else:

        form = UpdateAnalysis(request.form)

        new_title = form.title.data
        
        new_content = form.content.data  
        
        cursor2 = mysql.connection.cursor()

        sorgu2 = "Update shares Set title = %s,content = %s where id = %s"

        cursor2.execute(sorgu2,(new_title,new_content,id))

        mysql.connection.commit()

        cursor2.close()

        flash("İncelemeniz başarıyla güncellendi.","success")

        return redirect(url_for("control"))    

@app.route("/content/<string:id>", methods = ["GET","POST"])
@login_required
def content(id):

    form = CommentForm(request.form)
    
    cursor = mysql.connection.cursor()

    if request.method == "GET":
        
        sorgu = "Select * From shares where id = %s"

        result = cursor.execute(sorgu,(id,))

        if result > 0:

            data = cursor.fetchone()

            session["data"] = data

            sorgu2 = "Select * From comments where id = %s"

            result_comment = cursor.execute(sorgu2,(id,))

            comments = cursor.fetchall()

            sorgu3 = "Select * From liked where id = %s"

            cursor.execute(sorgu3,(id,))

            liked_data = cursor.fetchall()

            sorgu4 = "Select * From liked_shares where id = %s"

            result_share = cursor.execute(sorgu4,(id,))

            shares_data = cursor.fetchall()

            for comment in comments:
                likes = 0
                comment_id = comment["comment_id"]               
                for like_data in liked_data:
                    if like_data["comment_id"] == comment["comment_id"]:
                        likes += 1
                        if "logged_in" in session:
                            if session["username"] == like_data["liked_username"]:
                                session["he_liked_" + str(comment["comment_id"])] = True
                                     
                session["{}".format(comment_id)] = likes

            for share_data in shares_data:
                if share_data["liked_username"] == session["username"]:
                    session["liked_content_" + str(id)] = True 

            return render_template("content.html", data = data, comments = comments, result_comment = result_comment, form = form, liked_data = liked_data, result_share = result_share)

        else:

            flash("Böyle bir içerik bulunmuyor.","danger")

            return redirect(url_for("index")) 

    else:

        comment = form.comment.data

        username = session["username"]

        sorgu = "Insert into comments(id,username,content) VALUES(%s,%s,%s)"

        cursor.execute(sorgu,(id,username,comment))

        mysql.connection.commit()

        cursor.close()

        flash("Yorumunuz başarıyla gönderildi.","success")

        send_id = session["data"]["id"]

        return redirect(url_for("content",id = send_id))            

@app.route("/edit-comment/<string:id>", methods = ["GET","POST"])
@login_required
def edit_comment(id):

    cursor = mysql.connection.cursor()

    sorgu = "Select * From comments where comment_id = %s"

    cursor.execute(sorgu,(id,))

    data = cursor.fetchone()

    username = session["username"]

    entered_username = data["username"]

    if request.method == "GET":
        
        if username == entered_username:
            
            form = EditCommentForm()

            form.comment_form.data = data["content"]

            return render_template("editcomment.html",form = form)

        else:

            flash("Bu işlemi yapma yetkiniz yok.","danger")

            return redirect(url_for("index"))       
    else:
        
        form = EditCommentForm(request.form)

        content = form.comment_form.data

        sorgu = "Update comments set content = %s where comment_id = %s"

        cursor.execute(sorgu,(content,id,))

        mysql.connection.commit()

        cursor.close()

        flash("Yorumunuz başarıyla güncellendi.","success")

        send_id = data["id"]

        return redirect(url_for("content", id = send_id))

@app.route("/delete-comment/<string:id>")
@login_required
def delete_comment(id):


    cursor = mysql.connection.cursor()

    sorgu = "Select * From comments where comment_id = %s"

    result = cursor.execute(sorgu,(id,))

    data = cursor.fetchone()

    if result > 0:

        comment_username = data["username"]

        username = session["username"]

        if comment_username == username:

            sorgu = "Delete from comments where comment_id = %s"

            cursor.execute(sorgu,(id,))

            mysql.connection.commit()

            cursor.close()

            flash("Yorumunuz başarıyla silindi.","success")

            send_id = data["id"]

            return redirect(url_for("content", id = send_id))
    else:

        flash("Böyle bir işlem yapamazsınız.","danger")

        return redirect(url_for("index"))

@app.route("/like-comment/<string:id>/<string:comment_id>")
@login_required
def like_comment(id,comment_id):

    cursor = mysql.connection.cursor()

    sorgu = "Select * From comments where comment_id = %s"

    cursor.execute(sorgu,(comment_id,))

    comment_data = cursor.fetchone()

    sorgu2 = "Insert into liked(id,comment_id,username,liked_username) VALUES(%s,%s,%s,%s)"

    cursor.execute(sorgu2,(id,comment_data["comment_id"],comment_data["username"],session["username"]))

    mysql.connection.commit()
    
    session["he_liked_" + str(comment_id)] = True

    return redirect(url_for("content", id = id))

@app.route("/deletelike-comment/<string:id>/<string:comment_id>")
@login_required
def delete_like_comment(id,comment_id):

    cursor = mysql.connection.cursor()

    sorgu = "Select * From liked where comment_id = %s AND liked_username = %s"

    result = cursor.execute(sorgu,(comment_id,session["username"]))

    if result > 0:
        
        sorgu2 = "Delete from liked where comment_id = %s AND liked_username = %s"

        cursor.execute(sorgu2,(comment_id,session["username"]))

        mysql.connection.commit()

        cursor.close()

        session["he_liked_" + str(comment_id)] = False

        return redirect(url_for("content",id = id))
    
    else:
        flash("Böyle bir işlem yapamazsınız.","danger")
        return redirect(url_for("content",id = id))

@app.route("/like-analysis/<string:id>")
@login_required
def like_analysis(id):
    
    cursor = mysql.connection.cursor()

    sorgu = "Insert into liked_shares(id,liked_username) VALUES(%s,%s)"

    cursor.execute(sorgu,(id,session["username"]))

    mysql.connection.commit()

    cursor.close()

    return redirect(url_for("content",id = id))
    
@app.route("/delete_like-analysis/<string:id>")
def delete_like_analysis(id):
    
    cursor = mysql.connection.cursor()

    sorgu = "Delete from liked_shares where id = %s AND liked_username = %s"

    cursor.execute(sorgu,(id,session["username"]))

    mysql.connection.commit()

    cursor.close()

    session["liked_content_" + str(id)] = False

    return redirect(url_for("content",id = id))
    
@app.route("/users/<string:username>")
@login_required
def show_profile(username):

    cursor = mysql.connection.cursor()

    sorgu = "Select * From users where username = %s"

    result = cursor.execute(sorgu,(username,))

    if result > 0:
        
        users_data = cursor.fetchone()

        sorgu2 = "Select * From comments where username = %s"

        cursor.execute(sorgu2,(username,))

        comments_data = cursor.fetchall()
        
        total_comment = 0

        for comment in comments_data:
            if comment["username"] == username:
                total_comment += 1

        sorgu3 = "Select * From shares"

        cursor.execute(sorgu3)

        shares_data = cursor.fetchall()

        return render_template("userprofile.html", total_comment = total_comment,users_data = users_data,comments_data = comments_data,shares_data = shares_data)

    else:
        
        flash("Böyle bir kullanıcı bulunmuyor.","danger")

        return redirect(url_for("index"))

@app.route("/search", methods = ["GET","POST"])
def search():
    
    if request.method == "GET":
        
        return redirect(url_for("index"))
    
    else:

        keyword = request.form.get("keyword")

        cursor = mysql.connection.cursor()

        sorgu = "Select * From users where username like '%" + str(keyword) + "%'"

        result1 = cursor.execute(sorgu)

        users_data = cursor.fetchall()

        sorgu2 = "Select * From shares where title like '%" + str(keyword) + "%'"

        result2 = cursor.execute(sorgu2)

        shares_data = cursor.fetchall()

        if result1 == 0 and result2 == 0:

            flash("Aranan kelimeyi uygun eşleşme bulunamadı.","danger")

            return redirect(url_for("index"))     

        else:
            
            return render_template("search.html", keyword = keyword, users_data = users_data, shares_data = shares_data, result2 = result2, result1 = result1)

class RegisterForm(Form):
    name = StringField("Adınızı ve Soyadınızı Giriniz" , validators=[validators.Length(min = 5,max = 15)])
    age = StringField("Yaşınızı Giriniz",validators=[validators.Length(min=1, max=5)])
    email = StringField("Email Giriniz", validators = [validators.Email("Lütfen doğru bir e-posta giriniz.")])
    username = StringField("Kullanıcı Adınızı Giriniz", validators=[validators.DataRequired(message = "Kullanıcı adı kısmı boş bırakılamaz.")])
    password = PasswordField("Şifrenizi Giriniz.", validators=[validators.DataRequired(message = "Şifre kısmı boş bırakılamaz.")])

class LoginForm(Form):
    username = StringField("Kullanıcı Adınızı Giriniz", validators=[validators.Length(min = 3,max=20)])
    password = PasswordField("Şifrenizi Giriniz", validators=[validators.DataRequired(message = "Şifre kısmı boş bırakılamaz.")])

class ForgotMyPassword(Form):
    username = StringField("Kullanıcı adınızı giriniz", validators = [validators.Length(min = 3,max=20)])

class CorrectCode(Form):
    correctcode = StringField("Mailinize Gelen Doğrulama Kodunu Giriniz")

class NewPass(Form):
    new_password = PasswordField("Yeni Şifrenizi Giriniz" , validators = [validators.DataRequired(message = "Şifre kısmı boş bırakılamaz.")])    

class AddAnalysis(Form):
    title = StringField("İnceleme Başlığını Giriniz.", validators=[validators.Length(min = 3,max=200)])
    content = TextAreaField("İncelemenizi Yazınız.", validators=[validators.Length(min = 5, max = 1000)])

class UpdateAnalysis(Form):
    title = StringField("İnceleme Başlığını Giriniz.", validators=[validators.Length(min = 3,max=200)])
    content = TextAreaField("İncelemenizi Yazınız.", validators=[validators.Length(min = 5, max = 1000)])

class CommentForm(Form):
    comment = StringField("Bu inceleme Hakkında Yorumunuzu Belirtiniz.", validators=[validators.Length(min = 3, max = 150)])

class EditCommentForm(Form):
    comment_form = StringField("Yorumunuzu Güncelleyiniz.", validators=[validators.Length(min = 3, max = 150)])        

if __name__ == "__main__":
    app.run(debug=True)