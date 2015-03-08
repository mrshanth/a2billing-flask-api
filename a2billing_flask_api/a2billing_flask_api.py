import datetime
import hmac
import calendar
import ast
from werkzeug.security import generate_password_hash, \
        check_password_hash
from flask import Flask, g, render_template,session,redirect, url_for, \
        abort, flash
from flask_peewee.auth import Auth
from flask_peewee.db import Database
from flask_peewee.admin import Admin, ModelAdmin
from flask_peewee.rest import RestAPI, UserAuthentication, RestResource
from flask.ext.paginate import Pagination
from flask import request
import json
from peewee import *

# Configure your A2Billing database
DATABASE = {
    'name': 'mya2billing',
    'engine': 'peewee.MySQLDatabase',
    'user': 'root',
    'passwd': 'finch',
}

PER_PAGE = 10
CSS_FRAMEWORK = 'bootstrap3'
LINK_SIZE = 'sm'
API_LOGIN_ID = '2x9fyuSD8De'
TRANSACTION_KEY = '5e4yPAjUq75Z255C'
DOMAIN = 'http://127.0.0.1:8008'
# decide whether or not a single page returns pagination
SHOW_SINGLE_PAGE = False

class User(object):
         def __init__(self, username, password):
             self.username = username
             self.set_password(password)

         def set_password(self, password):
             self.pw_hash = generate_password_hash(password)

         def check_password(self, password):
             return check_password_hash(self.pw_hash, password)

app = Flask(__name__)
app.config.from_object(__name__)
# Set the secret key.  keep this really secret
# Default implementation stores all session data in a signed cookie. This requires that the secret_key is set
app.secret_key = 'THE_SECRET_KEY'

# Instantiate the db wrapper
db = Database(app)


#Home page lists the call records taken from the cc_call table in the database. The page shows the current balance, and also a date filter to the call records
@app.route('/home',methods=['GET','POST'])
def home():
    if not session.get('logged_in'):
    	abort(401)
    try:
        ccid = session['ccid']
        aa = Card.select(Card.credit).where(Card.id==ccid)
        session['credit'] = aa[0].credit
        tt = Call.select(Call.card_id).where(Call.card_id==ccid)
        total = tt.count()
        page, per_page, offset = get_page_items()
        if request.method == 'POST':
            session['drange'] = request.form['daterange']
            drange = ast.literal_eval(session['drange'])
            cc = Call.select(Call.dnid,Call.starttime,Call.stoptime).where(Call.card_id==ccid,Call.starttime>drange['start'], \
                    Call.starttime<drange['end']).order_by(Call.starttime.desc()).offset(offset).limit(10)
        else:
            try:
                drange = ast.literal_eval(session['drange'])
                cc = Call.select(Call.dnid,Call.starttime,Call.stoptime).where(Call.card_id==ccid,Call.starttime>drange['start'], \
                    Call.starttime<drange['end']).order_by(Call.starttime.desc()).offset(offset).limit(10)
            except:
                cc = Call.select(Call.dnid,Call.starttime,Call.stoptime).where(Call.card_id==ccid).order_by(Call.starttime.desc()).offset(offset).limit(10)
        entry = str(aa[0].credit)
        records = [dict(dnid=rec.dnid, stime=rec.starttime.strftime("%m/%d/%Y %H:%M"), \
                duration=datetime.datetime.strptime(rec.stoptime,"%Y-%m-%d %H:%M:%S")-rec.starttime) for rec in cc]
    except:
        records = []
        return render_template('dash2.html',entry=entry,records=records)
    return render_template('dash2.html',entry=entry,records=records,total=total,pageno=page)


#Login page, verifies for username and password from the cc_card table in the database. Hashing algorithm has been used for password
@app.route('/', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
	card = Card.filter(username=request.form['username'])
        try:
                if request.form['username'] != card[0].username:
                    error = 'Invalid username'
                elif check_password_hash(card[0].uipass,request.form['password']):
                    error = 'Invalid password'
                else:
                    session['logged_in'] = True
                    session['ccid'] = card[0].id
                    return redirect(url_for('home'))
        except:
            error = "Invalid Username"
            return render_template('login.html', error=error)
    elif session.get('logged_in'):
        print "Logged in"
        return redirect(url_for('home'))
    return render_template('login.html', error=error)

#The sign up page creates a new record in the cc_card table. Hashing algorith has been used for password encryption
@app.route('/signup', methods=['GET','POST'])
def signup():
    error=None
    if request.method == 'POST':
        try:
            me = User(request.form['username'],request.form['password'])
            card = Card(username = request.form['username'],useralias=request.form['username'],uipass=me.pw_hash,credit=5,expiredays=365,activated='t', \
                     status=1,lastname=request.form['lastname'],firstname=request.form['firstname'],address=request.form['address'], \
                     city=request.form['city'],state=request.form['state'],country=request.form['country'],zipcode=request.form['zipcode'], \
                     phone=request.form['username'],email=request.form['email'],sip_buddy=1)
            card.save()
            return redirect(url_for('login'))
        except: 
            error = "Username already exists"
            return render_template('signup.html',error=error)
    return render_template('signup.html',error=error)

#The list of DiD's are displayed for a card user. The user can edit the Destination and also change it to default value: SIP/cardno/did
@app.route('/did')
def did():
    if not session.get('logged_in'):
        abort(401)
    dnid = get_buy_dnid()
    if dnid != -99:
        uname = Card.select(Card.username).where(Card.id==session['ccid'])
        didno = Did.select(Did.did).where(Did.id==dnid)
        destin = "SIP/"+str(uname[0].username)+"/"+str(didno[0].did)
        DidDest.update(destination=destin).where(DidDest.id_cc_did==dnid,DidDest.id_cc_card==session['ccid']).execute()
    dd = DidDest.select(DidDest.destination,DidDest.activated,DidDest.id_cc_did).where(DidDest.id_cc_card==session['ccid'])
    records = [dict(dest=rec.destination,act = 'Yes' if rec.activated == 1 else 'No',dnid=rec.id_cc_did) for rec in dd]
    return render_template('did.html',records=records)

#The card user can change the Did's destination
@app.route('/editdid',methods=['GET','POST'])
def editdid():
    error=None
    if not session.get('logged_in'):
        abort(401)
    if request.method == 'GET':
        session['editdid'] = get_buy_dnid() 
    if request.method == 'POST':
        DidDest.update(destination=request.form['dest']).where(DidDest.id_cc_did==session['editdid'],DidDest.id_cc_card==session['ccid']).execute()
        return redirect(url_for('did'))
    return render_template('editdid.html',error=error)

#Payment method implemented using Authorize.net DPM method
@app.route('/payment',methods=['GET','POST'])
def payment():
     relayResponseUrl = '%s/relay' % DOMAIN
     print relayResponseUrl
     x_fp_sequence = '123'
     x_fp_timestamp = get_utc_timestamp_in_seconds()
     if request.method == 'POST':
         amount = request.form['x_amount']
     amount = 10
     x_fp_hash = generate_fingerprint(TRANSACTION_KEY, API_LOGIN_ID, x_fp_sequence, x_fp_timestamp, amount)
     return render_template('payment.html', apiLoginId=API_LOGIN_ID, relayResponseUrl=relayResponseUrl,
                                        x_fp_sequence=x_fp_sequence, x_fp_timestamp=x_fp_timestamp,
                                                                   x_fp_hash=x_fp_hash)

#Relay page for the payment gateway to respond
@app.route('/relay',methods=['POST'])
def relay():
    for key, value in request.form.iteritems():
        print "%s: %s" % (key, value)
    relayUrl = '%s/receipt?x_auth_code=%s' % (DOMAIN, request.form['x_auth_code'])
    return render_template('relay_response.html', relayUrl=relayUrl)

@app.route('/receipt')
def receipt():
       return render_template('receipt.html')

@app.route('/logout')
def logout():
    session.pop('logged_in',None)
    session.pop('ccid',None)
    session.pop('drange',None)
    session.pop('editdid',None)
    return redirect(url_for('login'))

def get_page_items():
        page = int(request.args.get('page', 1))
        per_page = 10 
        if not page:
            page = 1
        offset = (page - 1) * per_page
        return page, per_page, offset

def get_buy_dnid():
    dnid = int(request.args.get('dnid',-99))
    if not dnid:
        dnid = -99
    return dnid

def get_pagination(**kwargs):
        kwargs.setdefault('record_name', 'records')
        return Pagination(css_framework='bootstrap3',
                          link_size='sm',
                          show_single_page=False,
                          **kwargs
                          )

def generate_fingerprint(transactionKey, loginId, sequenceNumber, timestamp, amount):
    return hmac.new(transactionKey, "%s^%s^%s^%s^" % (loginId, sequenceNumber, timestamp, amount)).hexdigest()

def get_utc_timestamp_in_seconds():
    return calendar.timegm(datetime.datetime.utcnow().utctimetuple())

class CardGroup(db.Model):
    name = CharField()
    description = TextField(null=True)
    users_perms = IntegerField(default=0)
    id_agent = IntegerField(default=0)

    class Meta:
        db_table = 'cc_card_group'
    
class Card(db.Model):
    # user = ForeignKeyField(User, related_name='tweets')
    creationdate = DateTimeField(default=datetime.datetime.now)
    firstusedate = CharField(null=True)
    expirationdate = CharField(null=True)
    enableexpire = CharField(null=True)
    expiredays = CharField(null=True)
    username = CharField(null=False)
    useralias = CharField()
    uipass = CharField()
    credit = CharField()
    tariff = CharField()
    id_didgroup = CharField(null=True)
    activated = CharField(choices=(('f', 'False'), ('t', 'True')))
    status = IntegerField(default=1)
    lastname = CharField(default='')
    firstname = CharField(default='')
    address = CharField(default='')
    city = CharField(default='')
    state = CharField(default='')
    country = CharField(default='')
    zipcode = CharField(default='')
    phone = CharField(default='')
    email = CharField(default='')
    fax = CharField(default='')
    # inuse = CharField(null=True)
    simultaccess = IntegerField(default=0)
    currency = CharField(default='USD')
    # lastuse = CharField(null=True)
    # nbused = CharField(null=True)
    typepaid = IntegerField(default=0)
    creditlimit = IntegerField(default=0)
    voipcall = IntegerField(default=0)
    sip_buddy = IntegerField(default=0)
    iax_buddy = IntegerField(default=0)
    language = CharField(default='en')
    redial = CharField(default='')
    runservice = CharField(null=True)
    # nbservice = CharField(null=True)
    # id_campaign = CharField(null=True)
    # num_trials_done = CharField(null=True)
    vat = FloatField(null=False, default=0)
    # servicelastrun = CharField(null=True)
    # Using DecimalField produce an error
    initialbalance = FloatField(default=0.0)
    invoiceday = IntegerField(default=1)
    autorefill = IntegerField(default=0)
    loginkey = CharField(default='')
    mac_addr = CharField(default='00-00-00-00-00-00')
    id_timezone = IntegerField(default=0)
    tag = CharField(default='')
    voicemail_permitted = IntegerField(default=0)
    voicemail_activated = IntegerField(default=0)
    # last_notification = CharField(null=True)
    email_notification = CharField(default='')
    notify_email = IntegerField(default=0)
    credit_notification = IntegerField(default=-1)
    id_group = IntegerField(default=1)
    company_name = CharField(default='')
    company_website = CharField(default='')
    vat_rn = CharField(null=True)
    traffic = BigIntegerField(default=0)
    traffic_target = CharField(default='')
    # Using DecimalField produce an error
    discount = FloatField(default=0.0)
    # restriction = CharField(null=True)
    # id_seria = CharField(null=True)
    # serial = CharField(null=True)
    block = IntegerField(default=0)
    lock_pin = CharField(null=True)
    lock_date = DateTimeField(null=True)
    max_concurrent = IntegerField(default=10)
    # is_published = BooleanField(default=True)

    class Meta:
        db_table = 'cc_card'

class Call(db.Model):
    sessionid = CharField(default=0)
    uniqueid = CharField(null=False)
    card_id = IntegerField(null=False)
    nasipaddress = CharField(null=False)
    starttime = DateTimeField(default=datetime.datetime.now)
    stoptime = CharField(default="0000-00-00 00:00:00")
    sessiontime = IntegerField(null=True)
    calledstation = CharField(null=False)
    sessionbill = FloatField(null=True)
    id_tariffgroup = IntegerField(null=True)
    id_tariffplan = IntegerField(null=True)
    id_ratecard = IntegerField(null=True)
    id_trunk = IntegerField(null=True)
    sipiax = IntegerField(null=True)
    src = CharField(null=False)
    id_did = IntegerField(null=True)
    buycost = FloatField(null=True)
    id_card_package_offer = IntegerField(null=True)
    real_sessiontime = IntegerField(null=True)
    dnid = CharField(null=False)
    terminatecauseid = IntegerField(null=True)
    destination = IntegerField(null=True)

    class Meta:
        db_table = 'cc_call'

class Country(db.Model):
    id = IntegerField(primary_key=True)
    countrycode   = CharField() 
    countryprefix = CharField() 
    countryname   = CharField() 
    
    class Meta:
        db_table = 'cc_country'

    def __str__(self):
        return self.countryname


class Did(db.Model):
    id = IntegerField()
    id_cc_didgroup = IntegerField(null=False)
    id_cc_country_id = ForeignKeyField(Country,related_name='country',db_column='id_cc_country')
    activated = IntegerField(null=False)
    reserved  = IntegerField(null=False)
    iduser = IntegerField(null=False)
    did = CharField(null=False)
    creationdate = DateTimeField(default=datetime.datetime.now)
    startingdate = DateTimeField()
    expirationdate = DateTimeField()
    description = CharField()
    secondusedreal = IntegerField()
    billingtype = IntegerField()
    fixrate = FloatField()
    connection_charge = FloatField()
    selling_rate = FloatField()
    aleg_carrier_connect_charge = FloatField()
    aleg_carrier_cost_min = FloatField()
    aleg_retail_connect_charge = FloatField()
    aleg_retail_cost_min = FloatField()
    aleg_carrier_initblock = IntegerField()
    aleg_carrier_increment = IntegerField()
    aleg_retail_initblock = IntegerField()
    aleg_retail_increment = IntegerField()
    aleg_timeinterval = CharField()
    aleg_carrier_connect_charge_offp = FloatField()
    aleg_carrier_cost_min_offp = FloatField()
    aleg_retail_connect_charge_offp = FloatField()
    aleg_retail_cost_min_offp = FloatField()
    aleg_carrier_initblock_offp =  IntegerField()
    aleg_carrier_increment_offp = IntegerField()
    aleg_retail_initblock_offp = IntegerField()
    aleg_retail_increment_offp = IntegerField()
    max_concurrent = IntegerField()
    
    class Meta:
        db_table = 'cc_did'

class DidDest(db.Model):
    destination     = CharField() 
    priority        = IntegerField()      
    id_cc_card      = IntegerField() 
    id_cc_did       = IntegerField()   
    creationdate    = DateTimeField() 
    activated       = IntegerField()      
    secondusedreal  = IntegerField()      
    voip_call       = IntegerField()      
    validated       = IntegerField()      

    class Meta:
        db_table = 'cc_did_destination'


class CardAdmin(ModelAdmin):
    columns = ('username', 'creationdate',)


class CardGroupAdmin(ModelAdmin):
    columns = ('id', 'name',)

class CallAdmin(ModelAdmin):
    columns = ('card_id','sessionid','dnid')

class CountryAdmin(ModelAdmin):
    columns = ('id','countrycode','countryname')

class DidAdmin(ModelAdmin):
    columns = ('id','did','iduser','activated','reserved')

class DidDestAdmin(ModelAdmin):
    columns = ('destination','id_cc_card','id_cc_did','activated')


# create a special resource for users that excludes email and password
class CardResource(RestResource):
    # exclude = ('lock_pin',)

    def check_post(self):
        datajson = json.loads(request.data)
        if 'username' not in datajson or len(datajson['username']) == 0:
            return False
        if 'useralias' not in datajson or len(datajson['useralias']) == 0:
            return False
        if 'uipass' not in datajson or len(datajson['uipass']) == 0:
            return False
        if 'credit' not in datajson or len(datajson['credit']) == 0:
            return False
        if 'tariff' not in datajson or len(datajson['tariff']) == 0:
            return False

        return True


# create a special resource for users that excludes email and password
class UserResource(RestResource):
    exclude = ('password', 'email',)

# create an Auth object for use with our flask app and database wrapper
auth = Auth(app, db)

# instantiate the user auth
user_auth = UserAuthentication(auth, protected_methods=['GET', 'POST', 'PUT', 'DELETE'])
# create a RestAPI container
api = RestAPI(app, default_auth=user_auth)
# register the models
api.register(Card, CardResource, auth=user_auth)
api.register(CardGroup, auth=user_auth)
api.register(Call, auth=user_auth)
api.register(Did, auth=user_auth)
api.register(DidDest, auth=user_auth)
api.register(Country, auth=user_auth)
api.register(auth.User, UserResource, auth=user_auth)
api.setup()


admin = Admin(app, auth, branding='A2Billing API Admin Site')
admin.register(Card, CardAdmin)
admin.register(Call, CallAdmin)
admin.register(CardGroup, CardGroupAdmin)
admin.register(Did, DidAdmin)
admin.register(DidDest, DidDestAdmin)
admin.register(Country, CountryAdmin)
auth.register_admin(admin)
admin.setup()


if __name__ == '__main__':
    auth.User.create_table(fail_silently=True)
    # Note.create_table(fail_silently=True)
    try:
        admin = auth.User(username='admin', email='', admin=True, active=True)
        admin.set_password('admin')
        admin.save()
    except IntegrityError:
        print "User 'admin' already created!"

    app.debug = True
    app.run(host='0.0.0.0', port=8008)
    app.run()
