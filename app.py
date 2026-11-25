import os
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Flask, request, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import select

app = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET_BEFORE_DEPLOY")
db_url = os.environ.get("DATABASE_URL", "sqlite:///saraqeb_store.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "false").lower() == "true"
db = SQLAlchemy(app)

def now():
    return datetime.now(timezone.utc)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    balance = db.Column(db.Numeric(12, 2), default=Decimal("0.00"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(500), default="")
    price = db.Column(db.Numeric(12, 2), nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

class Topup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    method = db.Column(db.String(40), nullable=False)
    reference = db.Column(db.String(120), default="")
    status = db.Column(db.String(20), default="pending", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)
    reviewed_at = db.Column(db.DateTime(timezone=True))

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)
    total = db.Column(db.Numeric(12, 2), nullable=False)
    customer_data = db.Column(db.String(500), default="")
    status = db.Column(db.String(24), default="pending", nullable=False)
    supplier_order_id = db.Column(db.String(120), default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    kind = db.Column(db.String(30), nullable=False)
    note = db.Column(db.String(250), default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now, nullable=False)

def money(value):
    try:
        amount = Decimal(str(value)).quantize(Decimal("0.01"))
        if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000"):
            raise ValueError()
        return amount
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("المبلغ غير صالح")

def user_json(user):
    return {"id": user.id, "username": user.username, "is_admin": user.is_admin,
            "balance": str(user.balance), "currency": "USD"}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify(error="سجّل الدخول أولاً"), 401
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        user = db.session.get(User, session["user_id"])
        if not user or not user.is_admin:
            return jsonify(error="غير مصرح"), 403
        return fn(*args, **kwargs)
    return wrapper

@app.get("/")
def home():
    return jsonify(service="Saraqeb Store API", status="ready", version="0.1")

@app.get("/api/health")
def health():
    return jsonify(ok=True, database="configured")

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if len(username) < 3 or len(username) > 40:
        return jsonify(error="اسم المستخدم يجب أن يكون بين 3 و40 حرفاً"), 400
    if len(password) < 8:
        return jsonify(error="كلمة المرور يجب أن تكون 8 أحرف على الأقل"), 400
    if User.query.filter_by(username=username).first():
        return jsonify(error="اسم المستخدم مستخدم مسبقاً"), 409
    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    session["user_id"] = user.id
    return jsonify(user=user_json(user)), 201

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    user = User.query.filter_by(username=str(data.get("username", "")).strip()).first()
    if not user or not check_password_hash(user.password_hash, str(data.get("password", ""))):
        return jsonify(error="بيانات الدخول غير صحيحة"), 401
    session.clear()
    session["user_id"] = user.id
    return jsonify(user=user_json(user))

@app.post("/api/logout")
@login_required
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/me")
@login_required
def me():
    user = db.session.get(User, session["user_id"])
    return jsonify(user=user_json(user))

@app.get("/api/products")
def products():
    rows = Product.query.filter_by(active=True).order_by(Product.category, Product.name).all()
    return jsonify(products=[{"id":p.id,"name":p.name,"category":p.category,
                              "description":p.description,"price":str(p.price)} for p in rows])

@app.post("/api/topups")
@login_required
def create_topup():
    data = request.get_json(silent=True) or {}
    try:
        amount = money(data.get("amount"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    method = str(data.get("method", "")).strip()
    if method not in {"Sham Cash", "USDT BEP20", "Bank Transfer", "Other"}:
        return jsonify(error="طريقة الدفع غير معتمدة"), 400
    row = Topup(user_id=session["user_id"], amount=amount, method=method,
                reference=str(data.get("reference", ""))[:120])
    db.session.add(row)
    db.session.commit()
    return jsonify(message="تم إرسال طلب شحن الرصيد للمراجعة", topup_id=row.id, status=row.status), 201

@app.get("/api/topups")
@login_required
def my_topups():
    rows = Topup.query.filter_by(user_id=session["user_id"]).order_by(Topup.created_at.desc()).all()
    return jsonify(topups=[{"id":x.id,"amount":str(x.amount),"method":x.method,"status":x.status,
                            "created_at":x.created_at.isoformat()} for x in rows])

@app.get("/api/transactions")
@login_required
def transactions():
    rows = Transaction.query.filter_by(user_id=session["user_id"]).order_by(Transaction.created_at.desc()).all()
    return jsonify(transactions=[{"id":x.id,"amount":str(x.amount),"kind":x.kind,
                                  "note":x.note,"created_at":x.created_at.isoformat()} for x in rows])

@app.post("/api/orders")
@login_required
def create_order():
    data = request.get_json(silent=True) or {}
    product = db.session.get(Product, data.get("product_id"))
    if not product or not product.active:
        return jsonify(error="المنتج غير متاح"), 404
    try:
        qty = int(data.get("quantity", 1))
        if qty < 1 or qty > 100:
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify(error="الكمية غير صالحة"), 400
    total = (product.price * qty).quantize(Decimal("0.01"))
    user = db.session.get(User, session["user_id"])
    if user.balance < total:
        return jsonify(error="رصيدك غير كافٍ"), 400
    # No supplier is called here. The order is queued for admin review until API integration is tested.
    user.balance -= total
    row = Order(user_id=user.id, product_id=product.id, quantity=qty, total=total,
                customer_data=str(data.get("customer_data", ""))[:500], status="pending_review")
    db.session.add(row)
    db.session.add(Transaction(user_id=user.id, amount=-total, kind="purchase",
                               note=f"طلب #{row.id} - {product.name}"))
    db.session.commit()
    return jsonify(message="تم تسجيل الطلب للمراجعة اليدوية", order_id=row.id,
                   status=row.status, total=str(total)), 201

@app.get("/api/orders")
@login_required
def my_orders():
    rows = Order.query.filter_by(user_id=session["user_id"]).order_by(Order.created_at.desc()).all()
    return jsonify(orders=[{"id":x.id,"product_id":x.product_id,"quantity":x.quantity,
                            "total":str(x.total),"status":x.status,"created_at":x.created_at.isoformat()} for x in rows])

@app.get("/api/admin/summary")
@admin_required
def admin_summary():
    return jsonify(users=User.query.count(), products=Product.query.count(),
                   pending_topups=Topup.query.filter_by(status="pending").count(),
                   pending_orders=Order.query.filter_by(status="pending_review").count())

@app.get("/api/admin/topups")
@admin_required
def admin_topups():
    rows = Topup.query.order_by(Topup.created_at.desc()).limit(200).all()
    return jsonify(topups=[{"id":x.id,"user_id":x.user_id,"username":db.session.get(User,x.user_id).username,
                            "amount":str(x.amount),"method":x.method,"reference":x.reference,
                            "status":x.status} for x in rows])

@app.post("/api/admin/topups/<int:topup_id>/review")
@admin_required
def review_topup(topup_id):
    data = request.get_json(silent=True) or {}
    decision = data.get("decision")
    row = db.session.get(Topup, topup_id)
    if not row or row.status != "pending":
        return jsonify(error="الطلب غير موجود أو تمت مراجعته"), 404
    if decision not in {"approve", "reject"}:
        return jsonify(error="القرار غير صالح"), 400
    row.status = "approved" if decision == "approve" else "rejected"
    row.reviewed_at = now()
    if decision == "approve":
        user = db.session.get(User, row.user_id)
        user.balance += row.amount
        db.session.add(Transaction(user_id=user.id, amount=row.amount, kind="topup",
                                   note=f"اعتماد طلب شحن رصيد #{row.id}"))
    db.session.commit()
    return jsonify(ok=True, status=row.status)

@app.post("/api/admin/products")
@admin_required
def admin_create_product():
    data = request.get_json(silent=True) or {}
    name, category = str(data.get("name","")).strip(), str(data.get("category","")).strip()
    try:
        price = money(data.get("price"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if not name or not category:
        return jsonify(error="اسم المنتج والقسم مطلوبان"), 400
    row = Product(name=name[:120], category=category[:80],
                  description=str(data.get("description",""))[:500], price=price)
    db.session.add(row); db.session.commit()
    return jsonify(id=row.id, name=row.name), 201

@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    rows = Order.query.order_by(Order.created_at.desc()).limit(200).all()
    return jsonify(orders=[{"id":x.id,"user_id":x.user_id,"product_id":x.product_id,
                            "quantity":x.quantity,"total":str(x.total),"status":x.status,
                            "customer_data":x.customer_data} for x in rows])

@app.post("/api/admin/orders/<int:order_id>/status")
@admin_required
def update_order(order_id):
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in {"processing", "completed", "rejected"}:
        return jsonify(error="الحالة غير صالحة"), 400
    row = db.session.get(Order, order_id)
    if not row:
        return jsonify(error="الطلب غير موجود"), 404
    row.status = status
    db.session.commit()
    return jsonify(ok=True, status=row.status)

def initialize():
    with app.app_context():
        db.create_all()
        admin_name = os.environ.get("ADMIN_USERNAME")
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if admin_name and admin_password and not User.query.filter_by(username=admin_name).first():
            db.session.add(User(username=admin_name,
                                password_hash=generate_password_hash(admin_password),
                                is_admin=True))
            db.session.commit()

initialize()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
