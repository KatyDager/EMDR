import pymysql
pymysql.install_as_MySQLdb()
from flask import Flask, request, jsonify, make_response, redirect, url_for
#from flask_login import login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import bcrypt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)


from sqlalchemy.exc import IntegrityError
import requests

from flask_cors import CORS, cross_origin
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib


from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker
from flask import session as login_session

from flask_mail import Mail, Message


engine = create_engine(
    'mysql://bGeDAIbzII:784iGwYRWg@remotemysql.com/bGeDAIbzII',
    echo=True
)
Session = sessionmaker(bind=engine)
session = Session()

app = Flask(__name__)

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_USERNAME']='emdrtherapy234@gmail.com'
app.config['MAIL_PASSWORD']='emdrtherapy'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = False


CORS(app)

jwt1 = JWTManager(app)

app.config['SECRET_KEY'] = 'EMDRSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://bGeDAIbzII:784iGwYRWg@remotemysql.com/bGeDAIbzII'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(250), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(250))
    admin = db.Column(db.Boolean)
    firstname = db.Column(db.String(50))
    lastname  = db.Column(db.String(50))
    dateofbirth = db.Column(db.String(50))
    gender = db.Column(db.String(50))
    phonenumber  = db.Column(db.String(50))
    postalcode = db.Column(db.String(50))
    country = db.Column(db.String(50))

class ChatBotAns(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    accord = db.Column(db.String(10))
    s2 = db.Column(db.String(50))
    s3 = db.Column(db.String(550))
    s4 = db.Column(db.String(550))
    s5 = db.Column(db.String(550))
    s6 = db.Column(db.Integer)
    s7 = db.Column(db.Integer)
    s8 = db.Column(db.String(550))
    s9 = db.Column(db.Integer)
    s10 = db.Column(db.Integer)
    s11 = db.Column(db.String(550))
    s12 = db.Column(db.String(550))
    s13 = db.Column(db.Integer)
    s14 = db.Column(db.Integer)
    s15 = db.Column(db.String(1000))
    user_public_id = db.Column(db.String(255))
   

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
            print(token)

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})


    user = User.query.filter_by(public_id=public_id).first()


    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:        
        return make_response('Could not verify email or password', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('User does not exist', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
        
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=120)}, app.config['SECRET_KEY'],algorithm="HS256")

        return jsonify({'token' : token}, 200)
    
    print(user.password)
    print(auth.password)
    print(user)
    return make_response('Could not verify', 403, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@app.route('/register', methods=['POST'])
def register():
    try:
        email = request.json.get('email')
        password = request.json.get('password')
        repeat_password = request.json['repeat_password']
        firstname = request.json['firstname']
        lastname  = request.json['lastname']
        dateofbirth = request.json['dateofbirth']
        gender = request.json['gender']
        phonenumber  = request.json['phonenumber']
        postalcode = request.json['postalcode']
        country = request.json['country']
        
        
        if (repeat_password != password):
            return jsonify({'errorENG' : 'Passwords do not match!', 'errorRO' : 'Parolele nu sunt identice!'}), 400
        
        if not email:
            return jsonify({'errorENG' : 'No email provided!'}, {'errorRO' : 'Niciun email introdus!'}), 400
        if not password:
            return jsonify({'errorENG' : 'No password provided!'}, {'errorRO' : 'Nicio parola introdusa!'}), 400
        if not firstname:
            return jsonify({'errorENG' : 'No firstname provided!'}, {'errorRO' : 'Niciun prenume introdus!'}), 400
        if not lastname:
            return jsonify({'errorENG' : 'No lastname provided!'}, {'errorRO' : 'Niciun nume introdus'}), 400
        if not dateofbirth:
            return jsonify({'errorENG' : 'No dateofbirth provided!'},  {'errorRO' : 'Nicio zi de nastere introdusa!'}), 400
        if not gender:
            return jsonify({'errorENG' : 'No gender provided!'},  {'errorRO' : 'Niciun gen introdus!'}), 400
        if not phonenumber :
            return jsonify({'errorENG' : 'No phonenumber provided!'}, {'errorRO' : 'Niciun numar de telefon introdus!'}), 400
        if not postalcode:
            return jsonify({'errorENG' : 'No postalcode provided!'}, {'errorRO' : 'Niciun cod postal introdus!'}), 400
        if not country:
            return jsonify({'errorENG' : 'No country provided!'}, {'errorRO' : 'Nicio tara introdusa!'}), 400

        
        hashed = generate_password_hash(password, method='sha256')
        
        email=request.json.get('email')
        token = jwt.encode({'email' : email, 'password' : hashed, 'firstname':firstname, 'lastname':lastname, 'dateofbirth':dateofbirth, 'gender':gender, 'phonenumber':phonenumber, 'postalcode':postalcode, 'country':country,'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'],algorithm="HS256")

        msgReset = f'''To activate your account, visit the following link:
    {url_for('activateAccount', token=token, _external=True)}
    The link will expire in 30 minutes. 
    '''
    
        sender_email = "emdrtherapy234@gmail.com"
        receiver_email = email
        sender_pass = "emdrtherapy"
        
        msg = MIMEText(msgReset)
        
        msg['Subject'] = "Account activation" 
        msg['From'] = 'emdrtherapy234@gmail.com'
        msg['To'] = email
    
        
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
    
        try:
            server.login(sender_email, sender_pass)
            print("Login success")
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print("Email has been sent to ", receiver_email)  
            response = jsonify({'message':"The e-mail has been sent"})
    
    
            return response
    
        except Exception as e:
            print(e)
            response = jsonify({'error':'Something went wrong'})
            return response, 400
      
        return "Mail sent"
                  
        
    except IntegrityError:
        # the rollback func reverts the changes made to the db ( so if an error happens after we commited changes they will be reverted )
        db.session.rollback()
        return jsonify({'errorENG' :'User Already Exists'}, {'errorRO' : 'Un user cu acest email deja exista!'}), 400
    except AttributeError:
        return jsonify({'message' :'Provide an Email and Password in JSON format in the request body'}), 400


@app.route('/ActivateAccount/<token>', methods=['POST'])
def activateAccount(token):
    try:
        decoded=jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        public_id=str(uuid.uuid4())
        email=decoded.get("email")  
        hashed=decoded.get("password") 
        firstname=decoded.get("firstname") 
        lastname=decoded.get("lastname") 
        dateofbirth=decoded.get("dateofbirth") 
        gender=decoded.get("gender") 
        phonenumber=decoded.get("phonenumber") 
        postalcode=decoded.get("postalcode") 
        country=decoded.get("country") 
        admin=False

        print(decoded)
        
        user = User(public_id=public_id, email=email, password=hashed, firstname=firstname, lastname=lastname, admin=admin, dateofbirth=dateofbirth, gender=gender, phonenumber=phonenumber, postalcode=postalcode, country=country)
        db.session.add(user)
        db.session.commit()
    

        return jsonify({'message' : 'Your account has been activated!'})
    
    except jwt.ExpiredSignatureError as error:
        print (error)
        response=jsonify({'message' : "The link has expired"})
        return response


    
@app.route('/chatbotRO', methods=['GET', 'POST'])  
def chatRO():
    #Intrebari chatbot
    nume_chatbot = "Cum te numești?"
    varsta_chatbot = "Ce vârstă ai?"
    gen_chatbot = "Care este genul tău? Răspunde cu M pentru bărbat sau F pentru femeie."
    acord_chatbot = "Am nevoie de acordul tău pentru păstrarea datelor oferite, pentru a-ți putea oferi intervenția EMDR. Răspunde cu DA dacă ești de acord."
     
    s2_gaseste_amintirea_negativa_chatbot = "Identifică o emoție negativă care te copleșește adeseori, cu care te confrunți frecvent și cu care dorești să lucrezi astăzi? Poate fi vorba de teamă, furie, spaimă, rușine, neîncredere, disperare, tristețe etc, sau poate avea forma unei senzații, a unei imagini care apare pe ecranul minții tale sau orice altă formă care nu are un nume cunoscut, dar o simți, este acolo. Ia-ți câteva momente și gândeștete la acea emoție copleșitoare cu care ai vrea să lucrezi astăzi. Ia-ți un moment și stai cu această emoție. Răspunde cu DA, după ce ai reușit sa te idenifici cu acea emoție."
    s3_amintire_negativa_chatbot = "Pornind de la emoția pe care ai accesat-o, fă o călătorie în memoria ta, până în cele mai vechi timpuri din care păstrezi amintiri și caută primul moment din viața ta când te-ai simțit așa. Alege amintirea care îți apare prima oară în gând. Încearcă să-ți amintești evenimentul așa cum s-a întâmplat atunci. Este un eveniment care a influențat felul tău de a trăi emoțiile până în ziua de azi. Ia-ți timpul de care ai nevoie și vizualizează acel moment. Creează în minte o secvență, ca un cadru de film în care să pui această amintire. În momentul în care ai reușit să identifici acel moment, descrie-l pe scurt."
    s4_senzatii_corporale_chatbot = "Acum când te gândești la acel eveniment, la scena pe care ai identificat-o concentrează-ți atenția asupra corpului tău, asupra senzațiilor pe care le simți în corp atunci când te gândești la evenimentul respectiv. Pot fi tensiuni, poate fi apăsare, poate fi căldură sau frig, poate fi orice altă senzație așa cum apare ea în corpul tău. Încearcă totodată să vezi dacă sunt sunete care apar în conștiința ta atunci când te gândești la acel moment. Ia-ți timpul de care ai nevoie pentru a accesa senzațiile, sunetele, mirosurile pe care ți le evocă amintirea respectivă. În momentul în care ai reușit să le accesezi, notează-le aici."
    s5_credinta_negativa_chatbot = "Emoțiile noastre au adeseori în spatele lor gânduri, credințe pe care ni le-am dezvoltat pe baza experiențelor noastre de viață. Ia-ți câteva momente și încearcă să identifici ce gând sau credință negativă despre tine sau viață ai dezvoltat pornind de la acel moment evocat mai devreme. Poate fi o formulă precum:  „sunt o victimă”, „nu o să mai fiu niciodată normal”, „nu sunt bun de nimic”, „nu cred că voi trece peste asta”, „oamenii întotdeauna pleacă/ înșală etc”. Ia-ți timpul de care ai nevoie și identifică gândul, credința cu care ai rămas în urma acelui eveniment, pe care ți-o spui adeseori în gând. În momentul în care ai reușit să accesezi acea credință negativă, adaugă aici"
    s6_str_credinta_negativa_chatbot = "În momentele care urmează o să te rog să te gândești la acest gând/ credință negativă și să dai o notă, cât de adevărate simți acum, în acest moment,  aceste cuvinte, identificate mai devreme. pe o scară de la 1 la 7, unde 1 este complet fals și 7 – total adevărat:"
    s7_str_emotie_negativa_chatbot = "De asemenea, am să te rog să acorzi o notă și emoțiilor pe care le simți cu privire la acest eveniment. Pe o scală de la 0 la 10, unde 0 - nu este tulburător sau neutru și 10 este cea mai tulburătoare posibilă imagine pe care ți-o poți imagina, cât de tulburătoare se simte acum?"
    s8_tratament_EMDR_chatbot = "În următoarele minute va urma o primă sesiune de tratament. Te rog să îți concentrezi atenția asupra bilei de pe ecran și să o urmărești cu privirea. În timp ce te vei concentra pe mișcarea de pe ecran, gândește-te la evenimentul identificat mai devreme și dă-ți voie să-l retrăiești. Adu în sfera conștiinței tale toate imaginile și sunetele, senzațiile corporale și credința negativă pe care le-ai identificat mai devreme. Amintește-ți că e important ca în timp ce retrăiești incidentul, să urmărești cu privirea mișcarea de pe ecran."
    s9_str_credinta_nevativa_dupa_emdr = "Te rog să să evaluezi din nou, gândurile tale cu privire la incident, cât de adevărate simți acum aceste cuvinte (gândurile, credința negativă identificată anterior) pe o scară de la 1 la 7, unde 1 este complet fals și 7 – total adevărat:"
    s10_str_emotie_negativa_dupa_emdr_chatbot = "Te rog să evaluezi din nou emoțiile pe care le simți gândindu-te  la incident, pe o scală de la 0 la 10, unde 0 - nu este tulburător sau neutru și 10 este cea mai tulburătoare posibilă imagine pe care ți-o poți imagina, cât de tulburătoare se simte acum?"
    s11_credinta_pozitiva_chatbot = "Gândurile, credințele noastre sunt adeseori iraționale. Din faptul că cineva ne-a înșelat încrederea la un moment dat, dezvoltăm credința că toți oamenii înșală. Din faptul că viața ne-a fost pusă în pericol la un moment dat, tragem concluzia că primejdia ne pândește la orice pas. Și totuși există oameni care nu înșală, există locuri și momente în care suntem în siguranță. Ia-ți un moment, folosește-ți imaginația și creativitatea  și caută un nou gând, o nouă credință pozitivă, sănătoasă care să înlocuiască gândul/ credința negativă identificată mai devreme. Ia-ți timpul de care ai nevoie și caută o credință sănătoasă pe care să o așezi în conștiința ta în locul credinței negative cu care ai trăit de la acel eveniment. În momentul în care ai identificat-o, te rog să o adaugi aici"
    s12_tratament_emdr_chatbot = "În următoarele minute va urma o nouă sesiune de tratament. În timp ce te vei concentra pe mișcarea de pe ecran, încearcă să retrăiești evenimentul amintit mai devreme, imaginile și sunetele asociate, senzațiile corporale și credința pozitivă identificată. Amintește-ți că e important ca în timp ce retrăiești incidentul, să urmărești cu privirea mișcarea de pe ecran."
    s13_str_credinta_pozitiva_dupa_emdr_chatbot = "Te rog să să evaluezi din nou, gândurile tale cu privire la incident, cât de adevărate simți acum aceste cuvinte (gândurile, credința pozitivă identificată anterior) pe o scară de la 1 la 7, unde 1 este complet fals și 7 – total adevărat:"
    s14_str_emotie_negativa_dupa_emdr_chatbot = "Te rog să evaluezi din nou emoțiile pe care le simți gândindu-te  la incident, pe o scală de la 0 la 10, unde 0 - nu este tulburător sau neutru și 10 este cea mai tulburătoare posibilă imagine pe care ți-o poți imagina, cât de tulburătoare se simte acum?"
    s15_feedbackRO_chatbot = "Lasă-ne o impresie/sugestie despre intervenția de azi:"
    
    #lista intrebari chatbot
    intrebari_ro=[nume_chatbot, varsta_chatbot, gen_chatbot, acord_chatbot, s2_gaseste_amintirea_negativa_chatbot, s3_amintire_negativa_chatbot, s4_senzatii_corporale_chatbot, s5_credinta_negativa_chatbot, s6_str_credinta_negativa_chatbot, s7_str_emotie_negativa_chatbot, s8_tratament_EMDR_chatbot, s9_str_credinta_nevativa_dupa_emdr, s10_str_emotie_negativa_dupa_emdr_chatbot, s11_credinta_pozitiva_chatbot, s12_tratament_emdr_chatbot, s13_str_credinta_pozitiva_dupa_emdr_chatbot, s14_str_emotie_negativa_dupa_emdr_chatbot, s15_feedbackRO_chatbot]
    
    #intrebarile sunt serializate in format json si trimise
    return jsonify({'intrebari_ro':intrebari_ro})  
 
@app.route('/chatbotENG', methods=['GET', 'POST'])  
def chatENG(): 
    #Intrebari chatbot
    name_chatbot = "What’s your name?"
    age_chatbot = "How old are you?" 
    gender_chatbot = "What is your gender? Answer with M for Male or F for Female."
    accord_chatbot = "We need your permission to keep your answers stored in order to improve your EMDR intervention. Answer 'Yes' if you wish to give your permission."

    s2_find_negative_emotion_chatbot = "Please, identify a negative emotion that often overwhelms you, that you face frequently, and that you want to work with today. It can be fear, anger, fear, shame, distrust, despair, sadness etc., or it can be in the form of a sensation, an image that appears on the screen of your mind or any other form that does not have a known name, but you feel it, it is there. Take a few moments and think about that overwhelming emotion you would like to work with today. Take a moment and stay with this emotion. Answer YES, after you have managed to identify that emotion."
    s3_negative_emotion_chatbot = "Starting from the emotion you accessed, take a journey in your mind, back to the earliest times from which you keep memories and pinpoint the first moment in your life when you felt that way. Choose the memory that first comes to mind. Try to remember the event as it happened then. It is an event that has influenced your way of living emotions to this day. Take the time you need and visualize that moment. Create a sequence in your mind, like a movie frame in which you can visualize the memory. When you have managed to identify that moment, describe it briefly. "
    s4_body_sensation_chatbot = "Now that you are thinking about that event, focus on the scene you identified, focus on your body, on the sensations you feel in your body when you think about that event. There may be tensions, there may be pressure, it can be warm or cold, it can be any other sensation. Also try to see if there are sounds that appear in your consciousness when you think about that moment. Take the time you need to access the sensations, sounds, smells that your memory evokes. When you have managed to access them, write them down here."
    s5_negative_thought_chatbot = "Our emotions often have thoughts behind them, beliefs that we have developed based on our life experiences so far. Take a few moments and try to identify what negative thought or belief about you or life itself you have developed starting from that moment evoked earlier. It can be a formula like: 'I am a victim', 'I will never be normal again', 'I am not good at anything', 'I do not think I will get over it', 'people always leave/cheat, etc.' Take the time you need and identify the thought, the thought you were left with after that event, which stuck in your mind. The moment you managed to access that negative belief, add it here"
    s6_grade_negative_thought_chatbot = "In the following moments I will ask you to think about this negative thought / belief and grade, on a scale of 1 to 7 based on how real these thoughts/beliefs seem to you right now , where 1 is completely false and 7 - totally real:"
    s7_grade_negative_emotion_chatbot = "I will also ask you to give a note to the emotions you feel about this event. On a scale of 0 to 10, where 0 - is not disturbing/I feel neutral and 10 – it is the most disturbing image you can possibly imagine, how disturbing does it feel now?"
    s8_EMDR_treatment_chatbot = "In the next few minutes you will attend the therapy session. Please focus your attention on the ball on the screen and follow it as it moves. As you focus on the movement on the screen, think about the event identified earlier and allow yourself to relive it. Bring into the sphere of your consciousness all the images and sounds, bodily sensations, and negative thoughts/beliefs that you identified earlier. Remember that it is important to watch the movement on the screen while reliving the incident. Please write Ok when you are ready to start."
    s9_grade_negative_faith_after_emdr_chatbot = " Please re-evaluate your thoughts on the incident, how true you feel these words (thoughts, negative thoughts previously identified) on a scale of 1 to 7, where 1 is completely false and 7 - totally real:"
    s10_grade_negative_emotion_after_emdr_chatbot = " Please re-evaluate the emotions you feel thinking about the incident, on a scale from 0 to 10, where 0 - is not disturbing/I feel neutral and 10 – it is the most disturbing image you can possibly imagine. How disturbing does it feel now?"
    s11_positive_thought_chatbot = "Our thoughts and beliefs are often irrational. If someone deceived our trust at one point, we develop a feeling of mistrust and tend to believe all people are deceiving. If our lives were endangered at some point, we conclude that danger lurks at every step. And yet there are people who do not deceive or cheat and there are places in which we are safe. Take a moment, use your imagination and look for a new thought, a new positive, healthy belief to replace the negative thought / belief identified earlier. Take the time you need and look for a healthy belief to put in your conscience instead of the negative one you lived with since the event. Once you have identified it, please add it here"
    s12_emdr_treatment_chatbot = " A new treatment session will follow in the next few minutes. As you focus on the movement on the screen, try to relive the event mentioned earlier, the associated images and sounds, bodily sensations, and the identified positive faith. Remember that it is important to watch the movement on the screen while reliving the incident. Please write Ok when you are ready to start."
    s13_grade_positive_thought_after_emdr_chatbot = "Please re-evaluate your thoughts on the incident, how intense you feel these thoughts, positive beliefs previously identified on a scale of 1 to 7, where 1 is completely false and 7 – very intense:"
    s14_grade_negative_emotion_after_emdr_chatbot = " Please re-evaluate the emotions you feel thinking about the traumatic incident, on a scale of 0 to 10, where 0 - is not disturbing/ I feel neutral and 10 – it is the most disturbing image you can possibly imagine. How disturbing is it now? "
    s15_feedbackENG_chatbot = "Give us an impression / suggestion about today's intervention:"
    
    #lista intrebari chatbot
    intrebari_eng=[name_chatbot, age_chatbot, gender_chatbot, accord_chatbot, s2_find_negative_emotion_chatbot, s3_negative_emotion_chatbot, s4_body_sensation_chatbot, s5_negative_thought_chatbot, s6_grade_negative_thought_chatbot, s7_grade_negative_emotion_chatbot, s8_EMDR_treatment_chatbot, s9_grade_negative_faith_after_emdr_chatbot, s10_grade_negative_emotion_after_emdr_chatbot, s11_positive_thought_chatbot, s12_emdr_treatment_chatbot, s13_grade_positive_thought_after_emdr_chatbot, s14_grade_negative_emotion_after_emdr_chatbot, s15_feedbackENG_chatbot]
    
    #intrebarile sunt serializate in format json si trimise
    return jsonify({'intrebari_eng':intrebari_eng})  



@app.route("/chatbotAns", methods=["GET","POST"])
def chatAns():
        
    if request.is_json:
        # JSON=>Python dictionary
        dictQ = request.get_json()
        
        #AuthorizationB header for Bearer token where the public id is encoded        
        auth_h=request.headers.get('AuthorizationB')
        
        if not auth_h:
            return jsonify({'message' :'No authorization header'}), 401
        
        access_token = auth_h.split(" ")[-1]
        print(access_token)
        print("--------")
        
        #if the authorization header and the token exist, the token will be decoded, if not=>error
        if auth_h and access_token:
            public_id = jwt.decode(access_token,app.config['SECRET_KEY'],algorithms="HS256")
            public=public_id.get("public_id")
            print(public)
        else:
            return jsonify({'message' :'No authorization'}), 401
        
        #populate the dictionary with the answers and the public id of the user
        dictDB=ChatBotAns(**dictQ, user_public_id=public)
        db.session.add(dictDB)
        db.session.commit()
        
        # Print the dictionary
        print(dictQ)

        return "JSON received!", 200
    
    else:

        return "Request was not JSON", 400



@app.route("/sendemail", methods=["POST"])
def testfunct():
    if not(request.json.get('username') and request.json.get('phonenumber') and request.json.get('email') and request.json.get('message')):
            # return Response("{error:'Please fill in all fields'}", status = 400 , mimetype='application/json')
            response = jsonify({'error':'Please fill in all fields'})
            return response, 400
            
        
    username = request.json['username']
    phonenumber = request.json['phonenumber']
    email = request.json['email']
    message = request.json['message']
    
    sender_email = "emdrtherapy234@gmail.com"
    receiver_email = "emdrtherapy234@gmail.com"
    sender_pass = "emdrtherapy"
    
    msg = MIMEText(message)
    
    msg['Subject'] = "EMDR username:" + username + "   Phone Number:" + phonenumber + "   Email address:" + email
    msg['From'] = 'emdrtherapy234@gmail.com'
    msg['To'] = 'emdrtherapy234@gmail.com'

    
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    try:
        server.login(sender_email, sender_pass)
        print("Login success")
        server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Email has been sent to ", receiver_email)  
        response = jsonify({'message':"mail sent"})


        return response
    
    except Exception as e:
        print(e)
        response = jsonify({'error':'Something went wrong'})
        return response, 400


@app.route("/ForgotPassword", methods=['POST'])
def send_reset_email():
    email=request.json.get('email')
    token = jwt.encode({'email' : email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'],algorithm="HS256")
    # msgReset = Message('Password Reset Request',
    #               sender='emdrtherapy234@gmail.com',
    #               recipients=[email])
    msgReset = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
The link will expire in 30 minutes.
If you did not make this request then simply ignore this email and no changes will be made. 
'''

    sender_email = "emdrtherapy234@gmail.com"
    receiver_email = email
    sender_pass = "emdrtherapy"
    
    msg = MIMEText(msgReset)
    
    msg['Subject'] = "Password Reset Request" 
    msg['From'] = 'emdrtherapy234@gmail.com'
    msg['To'] = email

    
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    
    try:
        server.login(sender_email, sender_pass)
        print("Login success")
        server.sendmail(sender_email, receiver_email, msg.as_string())
        print("Email has been sent to ", receiver_email)  
        response = jsonify({'message':"The e-mail has been sent"})


        return response
    
    except Exception as e:
        print(e)
        response = jsonify({'error':'Something went wrong'})
        return response, 400
  
    return "Mail sent"
    
@app.route("/reset_password/<token>", methods=['PUT'])
def reset_token(token):    
    try:
        decoded=jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        emailU=decoded.get("email")  

        password = request.json.get('password')
        hashed = generate_password_hash(password, method='sha256')
        
        user = User.query.filter_by(email=emailU).first()
        user.password=hashed
    
        db.session.commit()

        return jsonify({'message' : 'Your password has been updated!'})
    
    except jwt.ExpiredSignatureError as error:
        print (error)
        response=jsonify({'message' : "The link has expired"})
        return response
       
    
if __name__ == '__main__':
    app.run()

