
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Lrs!@1994@35.241.101.34/turiean'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class addasset_data_model(db.Model):
    seq_no = db.Column(db.Integer,nullable=False,primary_key=True)
    assets_type = db.Column(db.String(25),nullable=False)
    assets_no = db.Column(db.String(25),nullable=False)
    assets_name = db.Column(db.String(80),nullable=False)
    date_of_purchase = db.Column(db.Date,nullable=False)
    warranty = db.Column(db.Date,nullable=False)

    def __init__(self,assets_type,assets_no,assets_name,date_of_purchase,warranty):
        self.assets_type = assets_type
        self.assets_no = assets_no
        self.assets_name = assets_name
        self.date_of_purchase = date_of_purchase
        self.warranty = warranty

class assetspecification_data_model(db.Model):
   id = db.Column(db.Integer,nullable=False,primary_key=True)
   assets_no = db.Column(db.String(25),nullable=False)
   assets_model = db.Column(db.String(80),nullable=False)
   assets_brand = db.Column(db.String(80),nullable=False)
   assets_specification = db.Column(db.String(1000),nullable=False)

   def __init__(self,assets_no,assets_model,assets_brand,assets_specification):
        self.assets_no = assets_no
        self.assets_model = assets_model
        self.assets_brand = assets_brand
        self.assets_specification = assets_specification

class assetcorespondance_data_model(db.Model):
    id = db.Column(db.Integer,nullable=False,primary_key=True)
    assets_no = db.Column(db.String(25),nullable=False)
    user_guide = db.Column(db.String(80),nullable=False)
    BillNo = db.Column(db.Integer,nullable=False)
    #paymentmode = db.Column(db.String(25),nullable=False)

    def __init__(self,assets_no,user_guide,BillNo ):
        self.assets_no = assets_no
        self.user_guide = user_guide
        self.BillNo = BillNo
        #self.paymentmode = paymentmode

class installments(db.Model):
    id = db.Column(db.Integer,nullable=False,primary_key=True)
    assets_no = db.Column(db.String(25),nullable=False)
    duedate = db.Column(db.Date,nullable=False)
    paymentdate = db.Column(db.Date,nullable=False)
    amount = db.Column(db.Integer,nullable=False)
    remainning = db.Column(db.Integer,nullable=False)
    
    

    def __init__(self,assets_no,duedate, paymentdate ,amount,remainning,):
        self.assets_no = assets_no
        self.duedate = duedate 
        self.paymentdate = paymentdate 
        self.amount = amount
        self.remainning = remainning
        
        
class WARRENTYDETAILS(db.Model):
    id = db.Column(db.Integer,nullable=False,primary_key=True)
    assets_no = db.Column(db.String(25),nullable=False)
    warrenty_start = db.Column(db.Date,nullable=False)
    ServiceAddrs = db.Column(db.String(200),nullable=False)
    servicecontact = db.Column(db.String(200),nullable=False)

    def __init__(self,assets_no,warrenty_start,ServiceAddrs,servicecontact):
        self.warrenty_start = warrenty_start
        self.assets_no = assets_no
        self.ServiceAddrs = ServiceAddrs
        self.servicecontact = servicecontact
        
class referancedoc(db.Model):
    Document_type = db.Column(db.String(25),nullable=False)
    DocumentSequence = db.Column(db.Integer,nullable=False,primary_key=True)
    document_no = db.Column(db.String(25),nullable=False)
    documentname = db.Column(db.String(200),nullable=False)
    issuedate = db.Column(db.Date,nullable=False)
    
    def __init__(self,Document_type,document_no, documentname , issuedate):
        self.Document_type = Document_type
        self.document_no = document_no
        self.documentname = documentname
        self.issuedate = issuedate
       
class legaldocu(db.Model):
    DocumentSequence = db.Column(db.Integer,nullable=False,primary_key=True)
    Document_type = db.Column(db.String(25),nullable=False)
    document_no = db.Column(db.String(25),nullable=False)
    issuedate = db.Column(db.Date,nullable=False)
    documentname = db.Column(db.String(200),nullable=False)
    

    def __init__(self,Document_type,document_no,issuedate,documentname):
        self.Document_type = Document_type
        self.document_no = document_no
        self.issuedate = issuedate
        self.documentname = documentname

class investmentinfo(db.Model):
    DocumentSequence = db.Column(db.Integer,nullable=False,primary_key=True)
    Document_type = db.Column(db.String(25),nullable=False)
    Investment_Number = db.Column(db.Integer,nullable=False) 
    document_no = db.Column(db.String(25),nullable=False)
    documentname = db.Column(db.String(200),nullable=False)
    issuedate = db.Column(db.Date,nullable=False)
    
    def __init__(self,Document_type,Investment_Number ,document_no,documentname,issuedate):
        self.Document_type = Document_type
        self.Investment_Number = Investment_Number
        self.document_no = document_no
        self.documentname = documentname
        self.issuedate = issuedate

class addtechnichaldocu(db.Model):
    DocumentSequence = db.Column(db.Integer,nullable=False,primary_key=True)
    Document_type = db.Column(db.String(25),nullable=False)
    document_no = db.Column(db.String(25),nullable=False)
    issuedate = db.Column(db.Date,nullable=False)
    documentname = db.Column(db.String(200),nullable=False)

    def __init__(self,Document_type,document_no,issuedate,documentname):
        self.Document_type = Document_type
        self.document_no = document_no
        self.issuedate = issuedate
        self.documentname = documentname
        
class addprojectdocu(db.Model):
    DocumentSequence = db.Column(db.Integer,nullable=False,primary_key=True)
    Document_type = db.Column(db.String(25),nullable=False)
    document_no = db.Column(db.String(25),nullable=False)
    issuedate = db.Column(db.Date,nullable=False)
    documentname = db.Column(db.String(200),nullable=False)
    
    
    def __init__(self,Document_type,document_no,issuedate,documentname):
        self.Document_type = Document_type
        self.document_no = document_no
        self.issuedate = issuedate
        self.documentname = documentname
        
        
class projectdetails(db.Model):
    project_number = db.Column(db.Integer,nullable=False,primary_key=True)
    project_name = db.Column(db.String(25),nullable=False)
    project_contact = db.Column(db.Integer,nullable=False)
    projectstart_Date = db.Column(db.Date,nullable=False)
    Project_address = db.Column(db.String(200),nullable=False)

    def __init__(self,project_name,project_contact,projectstart_Date,Project_address):
        self.project_name = project_name
        self.project_contact = project_contact
        self.projectstart_Date = projectstart_Date
        self.Project_address = Project_address

class investment(db.Model):
    id = db.Column(db.Integer,nullable=False,primary_key=True)
    date = db.Column(db.Date,nullable=False)
    cash_received_from = db.Column(db.String(25),nullable=False)
    paid_AS = db.Column(db.String(200),nullable=False)
    remarks = db.Column(db.String(200),nullable=False)

    def __init__(self,date,cash_received_from,paid_AS,remarks):
        self.cash_received_from = cash_received_from
        self.remarks = remarks
        self.date = date
        self.paid_AS = paid_AS

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
