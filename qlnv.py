import sqlite3
from tkinter import *
from tkinter import messagebox
from tkinter.simpledialog import askstring
import bcrypt
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
import random
import re
# Tải biến môi trường
load_dotenv()

ADMIN_KEY = os.getenv("ADMIN_KEY", "SECRET_ADMIN_KEY")
EMAIL_USER = os.getenv("EMAIL_USER")
PASSWORD_USER = os.getenv("PASSWORD_USER")


def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


def add_email_column():
    conn = sqlite3.connect("organization.db")
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE")
        conn.commit()
    except sqlite3.OperationalError:
        # Cột đã tồn tại
        pass
    finally:
        conn.close()


def setup_database():
    add_email_column()  # Thêm cột email nếu chưa có
    conn = sqlite3.connect("organization.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTERGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL,
        email TEXT UNIQUE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        hometown TEXT,
        address TEXT,
        position TEXT,
        dob TEXT,
        email TEXT UNIQUE 
    )
    """)
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("admin",))
    if cursor.fetchone()[0] == 0:
        default_password = hash_password("admin123")  # Mật khẩu mặc định
        cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                       ("admin", default_password, "admin", "admin@example.com"))

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        employee_id INTEGER NOT NULL,
        stars INTEGER CHECK(stars BETWEEN 1 AND 5),
        comment TEXT,
        reporter TEXT,
        FOREIGN KEY(employee_id) REFERENCES employees(id)
    )
    """)
    # Insert admin user with email

    conn.commit()
    conn.close()


def send_email(subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_USER
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
             server.starttls()
             server.login(EMAIL_USER, PASSWORD_USER)
             server.send_message(msg)
    except smtplib.SMTPException as e:
        messagebox.showerror(f"Lỗi", f"không thể gửi email: {e}")


def create_account_window():

    def is_valid_email(email):
         pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
         return re.match(pattern, email) is not None
    def create_account():
        username = username_entry.get().strip()
        password_raw = password_entry.get().strip()
        email = email_entry.get().strip()
        print("Username:", username)  # Debugging
        print("Email:", email)  # Debugging
        print("Raw Password:", password_raw)

        if len(username) < 6:
            messagebox.showerror("Lỗi", "Tên tài khoản phải có ít nhất 6 ký tự.")
            return
        if len(password_raw) < 8:
            messagebox.showerror("Lỗi", "Mật khẩu phải có ít nhất 8 ký tự.")
            return
        if not email:
            messagebox.showerror("Lỗi", "Email không thể để trống.")
            return

        password = hash_password(password_raw)

        conn = sqlite3.connect("organization.db")
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password, role, email) VALUES (?, ?, 'user', ?)",
                           (username, password, email,))
            conn.commit()
            messagebox.showinfo("Thành công", "Tạo tài khoản thành công!")
            create_window.destroy()

        except sqlite3.IntegrityError:
            messagebox.showerror("Lỗi", "Tên tài khoản hoặc email đã tồn tại.")
        except Exception as e:
            print("Error:", e)  # Debugging
            messagebox.showerror("Error", "An unexpected error occurred.")
        finally:
            conn.close()

    create_window = Toplevel()
    create_window.title("Tạo tài khoản")

    Label(create_window, text="Tên tài khoản:").pack(pady=5)
    username_entry = Entry(create_window)
    username_entry.pack(pady=5)

    Label(create_window, text="Mật khẩu:").pack(pady=5)
    password_entry = Entry(create_window, show="*")
    password_entry.pack(pady=5)

    Label(create_window, text="Email:").pack(pady=5)
    email_entry = Entry(create_window)
    email_entry.pack(pady=5)

    Button(create_window, text="Tạo tài khoản", command=create_account).pack(pady=10)


def change_password_window():
    def change_password():
        current_password = current_password_entry.get().strip()
        new_password = new_password_entry.get().strip()
        confirm_new_password = confirm_new_password_entry.get().strip()

        if new_password != confirm_new_password:
            messagebox.showerror("Lỗi", "Mật khẩu mới không khớp với mật khẩu xác nhận.")
            return

        conn = sqlite3.connect("organization.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (current_user,))
        user = cursor.fetchone()

        if user and verify_password(current_password, user[0]):
            hashed_new_password = hash_password(new_password)
            cursor.execute("UPDATE users SET password = ? WHERE username = ?",
                           (hashed_new_password, current_user,))
            conn.commit()
            messagebox.showinfo("Thành công", "Đổi mật khẩu thành công.")
            change_password_window.destroy()
        else:
            messagebox.showerror("Lỗi", "Mật khẩu hiện tại không đúng.")
        conn.close()

    change_password_window = Toplevel()
    change_password_window.title("Đổi mật khẩu")

    Label(change_password_window, text="Mật khẩu hiện tại:").pack(pady=5)
    current_password_entry = Entry(change_password_window, show="*")
    current_password_entry.pack(pady=5)

    Label(change_password_window, text="Mật khẩu mới:").pack(pady=5)
    new_password_entry = Entry(change_password_window, show="*")
    new_password_entry.pack(pady=5)

    Label(change_password_window, text="Xác nhận mật khẩu mới:").pack(pady=5)
    confirm_new_password_entry = Entry(change_password_window, show="*")
    confirm_new_password_entry.pack(pady=5)

    Button(change_password_window, text="Đổi mật khẩu", command=change_password).pack(pady=10)


def forgot_password_window():
    def send_reset_code():
        email = email_entry.get().strip()
        conn = sqlite3.connect("organization.db")
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            reset_code = random.randint(100000, 999999)
            message = f"Mã xác nhận của bạn là: {reset_code}"
            send_email("Mã xác nhận đổi mật khẩu", message)
            messagebox.showinfo("Mã xác nhận", "Mã xác nhận đã được gửi đến email của bạn.")
            reset_code_entry.pack(pady=5)
            Button(reset_window, text="Xác nhận", command=lambda: confirm_reset_code(user[0], reset_code)).pack(pady=10)
        else:
            messagebox.showerror("Lỗi", "Email không tồn tại.")

    def confirm_reset_code(username, reset_code):
        entered_code = reset_code_entry.get().strip()
        if entered_code == str(reset_code):
            new_password = new_password_entry.get().strip()
            confirm_new_password = confirm_new_password_entry.get().strip()

            if new_password != confirm_new_password:
                messagebox.showerror("Lỗi", "Mật khẩu mới không khớp với mật khẩu xác nhận.")
                return

            conn = sqlite3.connect("organization.db")
            cursor = conn.cursor()
            hashed_new_password = hash_password(new_password)
            cursor.execute("UPDATE users SET password = ? WHERE username = ?",
                           (hashed_new_password, username,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Thành công", "Mật khẩu đã được đổi thành công.")
            reset_window.destroy()
        else:
            messagebox.showerror("Lỗi", "Mã xác nhận không đúng.")

    reset_window = Toplevel()
    reset_window.title("Quên Mật Khẩu")

    Label(reset_window, text="Nhập email của bạn:").pack(pady=5)
    email_entry = Entry(reset_window)
    email_entry.pack(pady=5)

    Button(reset_window, text="Gửi mã xác nhận", command=send_reset_code).pack(pady=10)

    Label(reset_window, text="Nhập mã xác nhận:").pack(pady=5)
    reset_code_entry = Entry(reset_window)
    reset_code_entry.pack(pady=5)

    Label(reset_window, text="Mật khẩu mới:").pack(pady=5)
    new_password_entry = Entry(reset_window, show="*")
    new_password_entry.pack(pady=5)

    Label(reset_window, text="Xác nhận mật khẩu mới:").pack(pady=5)
    confirm_new_password_entry = Entry(reset_window, show="*")
    confirm_new_password_entry.pack(pady=5)


def login():
    global current_user

    def verify_user():
        username = username_entry.get().strip()
        password = password_entry.get()

        print("Attempting to log in with username:", username)  # Debugging


        conn = sqlite3.connect("organization.db")
        cursor = conn.cursor()
        cursor.execute("SELECT role, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and verify_password(password, user[1]):
            current_user = username
            current_role = user[0]
            login_window.destroy()
            messagebox.showinfo("Đăng Nhập Thành Công", f"Chào mừng, {username} ({current_role})!")
            app_main()
        else:
            messagebox.showerror("Lỗi", "Tên đăng nhập hoặc mật khẩu không đúng.")

    login_window = Tk()
    login_window.title("Đăng Nhập")

    Label(login_window, text="Tên đăng nhập:").pack(pady=5)
    username_entry = Entry(login_window)
    username_entry.pack(pady=5)

    Label(login_window, text="Mật khẩu:").pack(pady=5)
    password_entry = Entry(login_window, show="*")
    password_entry.pack(pady=5)

    Button(login_window, text="Đăng Nhập", command=verify_user).pack(pady=10)
    Button(login_window, text="Tạo tài khoản", command=create_account_window).pack(pady=10)
    Button(login_window, text="Quên mật khẩu", command=forgot_password_window).pack(pady=10)

    login_window.mainloop()


def app_main():
    global create_employee_window
    root = Tk()
    root.title("Hệ Thống Tổ Chức")

    Label(root, text=f"Chào mừng! Vai trò của bạn: {current_role}").pack(pady=20)
    Button(root, text="Thoát", command=root.destroy).pack(pady=10)

    def load_employees():
        employee_list.delete(0, END)
        conn = sqlite3.connect("organization.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, name FROM employees")
        employees = cursor.fetchall()
        conn.close()
        for emp in employees:
            employee_list.insert(END, f"{emp[0]} - {emp[1]}")

    def show_employee_details(event):
        selected = employee_list.curselection()
        if not selected:
            return
        emp_id = int(employee_list.get(selected[0]).split("-")[0])
        conn = sqlite3.connect("organization.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE id = ?", (emp_id,))
        employee = cursor.fetchone()
        conn.close()

        for widget in details_frame.winfo_children():
            widget.destroy()

        Label(details_frame, text=f"Tên: {employee[1]}", font=("Arial", 16)).pack(anchor="w", pady=5)
        Label(details_frame, text=f"Quê quán: {employee[2]}", font=("Arial", 12)).pack(anchor="w", pady=5)
        Label(details_frame, text=f"Địa chỉ: {employee[3]}", font=("Arial", 12)).pack(anchor="w", pady=5)
        Label(details_frame, text=f"Chức vụ: {employee[4]}", font=("Arial", 12)).pack(anchor="w", pady=5)
        Label(details_frame, text=f"Ngày sinh: {employee[5]}", font=("Arial", 12)).pack(anchor="w", pady=5)

        if current_role == "admin":
            Button(details_frame, text="Xem Phản Hồi", command=lambda: view_feedback(emp_id)).pack(pady=5)
            Button(details_frame, text="Xóa Nhân Viên", command=lambda: delete_employee(emp_id)).pack(pady=5)
        Button(details_frame, text="Bình Chọn", command=lambda: vote_employee(emp_id)).pack(pady=5)
        Button(details_frame, text="Bình Luận", command=lambda: comment_employee(emp_id)).pack(pady=5)

    def delete_employee(emp_id):
        if messagebox.askyesno("Xóa nhân viên", "Bạn có chắc chắn muốn xóa nhân viên này không?"):
            conn = sqlite3.connect("organization.db")
            cursor = conn.cursor()
            cursor.execute("DELETE FROM employees WHERE id = ?", (emp_id,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Thành công", "Nhân viên đã được xóa.")
            load_employees()

    def vote_employee(emp_id):
        vote_window = Toplevel(root)
        vote_window.title("Bình Chọn Nhân Viên")

        Label(vote_window, text="Đánh giá (1-5 sao):").pack(pady=5)
        stars = Entry(vote_window)
        stars.pack(pady=5)

        def submit_vote():
            try:
                rating = int(stars.get())
                if rating < 1 or rating > 5:
                    raise ValueError

                conn = sqlite3.connect("organization.db")
                cursor = conn.cursor()
                cursor.execute("INSERT INTO votes (employee_id, stars, reporter) VALUES (?, ?, ?)",
                               (emp_id, rating, current_user,))
                conn.commit()
                conn.close()
                messagebox.showinfo("Thành công", "Bình chọn đã được gửi!")
                vote_window.destroy()
            except ValueError:
                messagebox.showerror("Lỗi", "Vui lòng nhập một số hợp lệ từ 1 đến 5.")

        Button(vote_window, text="Gửi", command=submit_vote).pack(pady=10)

    def comment_employee(emp_id):
        comment_window = Toplevel(root)
        comment_window.title("Bình Luận về Nhân Viên")

        Label(comment_window, text="Nhập bình luận của bạn:").pack(pady=5)
        comment = Entry(comment_window, width=50)
        comment.pack(pady=5)

        def submit_comment():
            user_comment = comment.get()
            conn = sqlite3.connect("organization.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO votes (employee_id, comment, reporter) VALUES (?, ?, ?)",
                           (emp_id, user_comment, current_user,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Thành công", "Bình luận đã được gửi!")
            comment_window.destroy()

        Button(comment_window, text="Gửi", command=submit_comment).pack(pady=10)

    def view_feedback(emp_id):
        feedback_window = Toplevel(root)
        feedback_window.title("Phản Hồi về Nhân Viên")

        conn = sqlite3.connect("organization.db")
        cursor = conn.cursor()
        cursor.execute("SELECT stars, comment, reporter FROM votes WHERE employee_id = ?", (emp_id,))
        feedback = cursor.fetchall()
        conn.close()

        if not feedback:
            Label(feedback_window, text="Không có phản hồi nào được tìm thấy.").pack(pady=10)
        else:
            for fb in feedback:
                Label(feedback_window, text=f"Sao: {fb[0]}, Bình luận: {fb[1]}, Bởi: {fb[2]}").pack(anchor="w", pady=5)

    employee_list = Listbox(root, width=40, height=20)
    employee_list.pack(side=LEFT, padx=10, pady=10)
    employee_list.bind('<<ListboxSelect>>', show_employee_details)

    details_frame = Frame(root)
    details_frame.pack(side=RIGHT, fill=BOTH, expand=True)

    Button(root, text="Đổi mật khẩu", command=change_password_window).pack(pady=10)

    if current_role == "admin":
        Button(root, text="Thêm Nhân Viên", command=create_employee_window).pack(pady=10)

    def create_employee_window():
        def add_employee():
            name = name_entry.get().strip()
            hometown = hometown_entry.get().strip()
            address = address_entry.get().strip()
            position = position_entry.get().strip()
            dob = dob_entry.get().strip()

           with sqlite3.connect("organization.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO employees (name, hometown, address, position, dob) VALUES (?, ?, ?, ?, ?)",
                           (name, hometown, address, position, dob,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Thành công", "Nhân viên đã được thêm!")
            add_window.destroy()
            load_employees()

        add_window = Toplevel(root)
        add_window.title("Thêm Nhân Viên")

        Label(add_window, text="Tên:").pack(pady=5)
        name_entry = Entry(add_window)
        name_entry.pack(pady=5)

        Label(add_window, text="Quê quán:").pack(pady=5)
        hometown_entry = Entry(add_window)
        hometown_entry.pack(pady=5)

        Label(add_window, text="Địa chỉ:").pack(pady=5)
        address_entry = Entry(add_window)
        address_entry.pack(pady=5)

        Label(add_window, text="Chức vụ:").pack(pady=5)
        position_entry = Entry(add_window)
        position_entry.pack(pady=5)

        Label(add_window, text="Ngày sinh:").pack(pady=5)
        dob_entry = Entry(add_window)
        dob_entry.pack(pady=5)

        Button(add_window, text="Thêm Nhân Viên", command=add_employee).pack(pady=10)

    def on_closing():
        if messagebox.askokcancel("Thoát", "Bạn có muốn thoát không?"):
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    load_employees()
    root.mainloop()


if __name__ == "__main__":
    setup_database()
    login()
