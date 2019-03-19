from flask import Flask, request, render_template, url_for, redirect
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_uploads import UploadSet, configure_uploads, ALL
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length

from forms import AddAsset, ProjectDetail, WarrentyDetail, ReferanceDoc, LegalDocu, InvestmentInfo, AddProjectDocument, \
    AddTechDocument, AssetSpecification, AssetCorrespondance, Investment, Installment
from sa import db, addasset_data_model, User, investment, legaldocu, investmentinfo, installments, \
    assetcorespondance_data_model, projectdetails, assetspecification_data_model, addprojectdocu, addtechnichaldocu, \
    referancedoc, WARRENTYDETAILS

app = Flask(__name__)
files = UploadSet('files', ALL)

app.config['UPLOADED_FILES_DEST'] = 'uploads'
configure_uploads(app, files)
app.config['SECRET_KEY'] = '4546757868697970'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Lrs!@1994@35.241.101.34/turiean'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@app.route('/AddAsset' , methods = ['GET' , 'POST'])
def AddAssetForm():
        form = AddAsset()
        if request.method == 'POST':
            dataAssettype = request.form['Assettype']
            dataAssetname = request.form['Assetname']
            dataAssetnumber = request.form['Assetnumber']
            dataDateofPurchase = request.form['DateofPurchase']
            dataAssestWarrentyUpto = request.form['AssestWarrentyUpto']
            entry = addasset_data_model(dataAssettype, dataAssetname , dataAssetnumber , dataDateofPurchase , dataAssestWarrentyUpto)
            db.session.add(entry)
            db.session.commit()
            return redirect(url_for('AddAssetForm'))
        return render_template('AddAsset.html' , form= form)

@app.route('/ProjectDetails' , methods = ['GET' , 'POST'])
def ProjectDetailForm():
    form = ProjectDetail()
    if request.method == 'POST':
        dataProjectName = request.form['ProjectName']
        dataProjectContact = request.form['ProjectContact']
        dataProjectStartDate = request.form['ProjectStartDate']
        dataProjectAddress = request.form['ProjectAddress']
        entry = projectdetails(dataProjectName , dataProjectContact, dataProjectStartDate , dataProjectAddress)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('ProjectDetailForm'))
    return render_template('Project_Detail.html' , form= form)

@app.route('/AddProDoc' , methods = ['GET' , 'POST'])
def AddProDocForm():
    form = AddProjectDocument()
    if request.method == 'POST' and 'Attachment' in request.files:
        dataDocumentType = request.form['DocumentType']
        dataAttachment = files.save(request.files['Attachment'])
        dataDocumentNumber = request.form['DocumentNumber']
        dataIssueDate = request.form['IssueDate']
        dataDocumentName = request.form['DocumentName']
        entry = addprojectdocu(dataDocumentType , dataDocumentNumber ,dataIssueDate , dataDocumentName )
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('AddProDocForm'))
    return render_template('Add_Project_Document.html' , form= form)

@app.route('/AddTechDocument' , methods = ['GET' , 'POST'])
def AddTechDocumentForm():
    form = AddTechDocument()
    if request.method == 'POST' and 'Attachment' in request.files:
        dataDocumentType = request.form['DocumentType']
        dataAttachment = files.save(request.files['Attachment'])
        dataDocumentNumber = request.form['DocumentNumber']
        dataIssueDate = request.form['IssueDate']
        dataDocumentName = request.form['DocumentName']
        entry = addtechnichaldocu(dataDocumentType , dataDocumentNumber ,dataIssueDate , dataDocumentName )
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('ProjectDetailForm'))
    return render_template('Add_Technical_Document.html' , form= form)

@app.route('/AssetSpecification' , methods = ['GET' , 'POST'])
def AssetSpecificationForm():
    form = AssetSpecification()
    if request.method == 'POST':
        dataAssetNumber = request.form['AssetNumber']
        dataModel = request.form['Model']
        dataBrand = request.form['Brand']
        dataSpecifications = request.form['Specifications']
        entry = assetspecification_data_model(dataAssetNumber, dataModel , dataBrand , dataSpecifications)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('AssetSpecificationForm'))
    return render_template('Asset_Specification.html' , form= form)

@app.route('/AssetCorrespondance' , methods = ['GET' , 'POST'])
def AssetCorrespondanceForm():
    form = AssetCorrespondance()
    if request.method == 'POST' and 'WarrentyCard' in request.files:
        dataAssetNumber = request.form['AssetNumber']
        dataUserGuide = request.form['UserGuide']
        dataWarrentyCard = files.save(request.files['WarrentyCard'])
        dataBillNumber = request.form['BillNumber']
        entry = assetcorespondance_data_model(dataAssetNumber, dataUserGuide  , dataBillNumber )
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('AssetCorrespondanceForm'))
    return render_template('Assets_Correspondance.html' , form= form)

@app.route('/Investment' , methods = ['GET' , 'POST'])
def InvestmentForm():
    form = Investment()
    if request.method == 'POST':
        dataDate = request.form['Date']
        dataCashRecived = request.form['CashRecived']
        dataPaid = request.form['Paid']
        dataRemark = request.form['Remark']
        entry = investment(dataDate, dataCashRecived , dataPaid , dataRemark)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('InvestmentForm'))
    return render_template('Investment.html', form= form)

@app.route('/Installment', methods = ['GET' , 'POST'])
def InstallmentForm():
    form = Installment()
    if request.method == 'POST'and 'PaymentRecpt' in request.files:
        dataAssetNumber = request.form['AssetNumber']
        dataDueDate = request.form['DueDate']
        dataPayment = request.form['Payment']
        dataEnterAmt = request.form['EnterAmt']
        dataRemBal = request.form['RemBal']
        dataPaymentRecpt = files.save(request.files['PaymentRecpt'])
        entry = installments(dataAssetNumber, dataDueDate , dataPayment , dataEnterAmt , dataRemBal)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('InstallmentForm'))
    return render_template('Installments.html' , form= form)

@app.route('/InvestmentInfo' , methods = ['GET' , 'POST'])
def InvestmentInfoForm():
    form = InvestmentInfo()
    if request.method == 'POST'and 'Attachment' in request.files:
        dataDocumentType = request.form['DocumentType']
        dataInvestmentNum = request.form['InvestmentNum']
        dataDocumentNumber = request.form['DocumentNumber']
        dataDocumentName = request.form['DocumentName']
        dataIssueDate = request.form['IssueDate']
        dataAttachment = files.save(request.files['Attachment'])
        entry = investmentinfo(dataDocumentType, dataInvestmentNum , dataDocumentNumber ,dataDocumentName , dataIssueDate)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('InvestmentInfoForm'))
    return render_template('Investment_Info.html' , form= form)

@app.route('/LegalDocument' , methods = ['GET' , 'POST'])
def LegalDocumentForm():
    form = LegalDocu()
    if request.method == 'POST' and 'Attachment' in request.files:
        dataDocumentType = request.form['DocumentType']
        dataDocumentNumber = request.form['DocumentNumber']
        dataIssueDate = request.form['IssueDate']
        dataDocumentName = request.form['DocumentName']
        dataAttachment = files.save(request.files['Attachment'])
        entry = legaldocu(dataDocumentType , dataDocumentNumber , dataIssueDate , dataDocumentName)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('LegalDocumentForm'))
    return render_template('Legal_Document.html' , form= form)

@app.route('/ReferanceDocument' , methods = ['GET' , 'POST'])
def ReferanceDocumentForm():
    form = ReferanceDoc()
    if request.method == 'POST' and 'Attachment' in request.files:
        dataDocumentType = request.form['DocumentType']
        dataDocumentNumber = request.form['DocumentNumber']
        dataDocumentName = request.form['DocumentName']
        dataIssueDate = request.form['IssueDate']
        dataAttachment = files.save(request.files['Attachment'])
        entry = referancedoc(dataDocumentType , dataDocumentNumber, dataDocumentName , dataIssueDate)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('ReferanceDocumentForm'))
    return render_template('Referance_Document.html' , form= form)

@app.route('/WarrentyDetail' , methods = ['GET' , 'POST'])
def WarrentyDetailForm():
    form = WarrentyDetail()
    if request.method == 'POST':
        dataAssetNum = request.form['AssetNum']
        dataWarrentyStart = request.form['WarrentyStart']
        dataServiceAddrs = request.form['ServiceAddrs']
        dataServiceCentre = request.form['ServiceCentre']
        entry = WARRENTYDETAILS(dataAssetNum, dataWarrentyStart , dataServiceAddrs , dataServiceCentre)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('WarrentyDetailForm'))
    return render_template('Warrenty_Detail.html' , form= form)

@app.route('/')
def index():
    return render_template('TDM_Home.html')

@app.route('/TDM_Home')
def TDM_Home():
    return render_template('Nav_Bar.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
    submit = SubmitField('Login')
class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Sign Up')



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('TDM_Home'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('TDM_Home'))
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('dashboard'))


