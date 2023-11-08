import os
from flask import Flask,request,session,jsonify,render_template,redirect,Response,url_for
from werkzeug.middleware.proxy_fix import ProxyFix
import json
import jwt
import datetime
import requests
import mysql.connector
import pandas as pd
from datetime import datetime

with open('config.json') as config_file:
  config = json.load(config_file)

with open("./certs/privateRSA.pem",'r') as f:
  private_key = f.read()

with open("./certs/publicRSA.pub",'r') as f:
  public_key = f.read()

hubs = config['hubs']

api = Flask(__name__)
api.secret_key = config['app']['secret_key']
api.wsgi_app = ProxyFix(api.wsgi_app, x_proto=1, x_host=1)

# METHODS

def getDbInstance():
  mydb = mysql.connector.connect(
    host=config['db']['host'],
    user=config['db']['user'],
    passwd=config['db']['password'],
    database=config['db']['database'],
    auth_plugin="mysql_native_password"
  )
  return mydb, mydb.cursor()

def setDiscordRoleAndName(discordID, displayName):
  headers = {
    'Authorization' : f'Bot {config["discord"]["dicordAuthBearer"]}',
    'User-Agent' : config["discord"]["discordUserAgent"],
    'Content-Type' : 'application/json'
  }
  requests.put("https://discord.com/api/v10/guilds/{guildID}/members/{userID}/roles/{roleID}".format(guildID=config['discord']['verifiedRoleGuildID'],userID=discordID,roleID=config['discord']['verifiedRoleID']),headers=headers)
  data = {
    "nick" : displayName
  }
  requests.patch("https://discord.com/api/v10/guilds/{guildID}/members/{userID}".format(guildID=config['discord']['verifiedRoleGuildID'],userID=discordID),headers=headers,json=data)
  return None

def getDbUserFromDiscordID(discordID):
  mydb, mycursor = getDbInstance()
  dbDF = pd.read_sql("SELECT * FROM users WHERE discord = '{}'".format(discordID), mydb)
  if len(dbDF) > 0:
    return dbDF.to_dict('records')[0]
  return False

# ROUTES

@api.route("/faceitCallback", methods=['GET','POST'])
def faceitCallback():
  authCode = request.args.get('code', default="")
  stateToken = request.args.get('state', default="")
  try:
    jwtToken = jwt.decode(stateToken, public_key, algorithms=['RS256'])
  except:
    return jsonify({"error":"Unable to verify state token received from accounts.faceit.com. It was probably altered."})
  data = {
    "code" : authCode,
    "grant_type" : "authorization_code"
  }
  headers = {
    "Content-type" : "application/x-www-form-urlencoded"
  }
  r = requests.post("https://api.faceit.com/auth/v1/oauth/token", headers=headers, auth=(config['faceitTokens']['faceitClientID'], config['faceitTokens']['faceitClientSecret']), data=data).json()
  if not 'id_token' in r:
    return jsonify({"error":"Faceit authorization failed. Retry."})
  user = jwt.decode(r['id_token'], 'secret', algorithms=['RS256'], verify=False)
  
  #Check if faceit ID is already registered
  mydb, mycursor = getDbInstance()
  sql = "SELECT faceit FROM users WHERE faceit = '{}'".format(user['guid'])
  mycursor.execute(sql)
  myresult = mycursor.fetchall()
  if user['guid'] not in str(myresult):
    final = {}
    final['discord'] = jwtToken
    final['faceit'] = user
    final['givenRole'] = []
    for hub in hubs:
      # Give hub role
      headers = {
        "Authorization" : "Bearer {}".format(config['faceitTokens']['faceitAuthBearer']),
        "Content-Type" : "application/json;charset=UTF-8"
      }
      data = {
        "roles" : hubs[hub]
      }
      r = requests.put('https://api.faceit.com/hubs/v1/hub/{hub}/membership/{userID}'.format(hub=hub,userID=user['guid']), headers=headers, json=data).json()
      final['givenRole'].append(r)
    hasOne = False
    for roles in final['givenRole']:
      if not 'errors' in roles:
        hasOne = True
    if not hasOne:
      return redirect(f"https://{config['app']['domain']}/warface?error=faceithubs", code=302)
    
    setDiscordRoleAndName(final['discord']['id'], final['faceit']['nickname'] + " | " + final['discord']['wfnickname'])
    
    sql = "INSERT INTO users (game, discord, faceit_name, faceit, csid) VALUES ('{game}', '{discord}', '{faceit_name}', '{faceit}', '{csid}')".format(game=final['discord']['wfnickname'],discord=final['discord']['id'],faceit_name=final['faceit']['nickname'],faceit=final['faceit']['guid'],csid=final['discord']['wfcsid'])
    mycursor.execute(sql)
    mydb.commit()
    #return jsonify(final)
    encryptedToken = jwt.encode(final, private_key, algorithm='RS256').decode("utf-8")
    return redirect(f"https://{config['app']['domain']}/completed?state={encryptedToken}", code=302)
  else:
    return redirect(f"https://{config['app']['domain']}/warface?error=faceitalreadyregistered", code=302)

@api.route("/discordCallback", methods=['GET','POST'])
def discordCallback():
  authCode = request.args.get('code', default="")
  stateToken = request.args.get('state', default="")
  data = {
    "grant_type" : "authorization_code",
    "client_id" : config['discord']['discordClientID'],
    "client_secret" : config['discord']['discordClientSecret'],
    "redirect_uri" : f"https://{config['app']['domain']}/discordCallback",
    "code" : authCode
  }
  headers = {
    "Content-Type" : "application/x-www-form-urlencoded"
  }
  r = requests.post("https://discordapp.com/api/oauth2/token",data=data).json()
  if not 'access_token' in r:
    return jsonify({"error":"Discord authorization failed. Retry."})
  headers = {
    "Authorization" : "Bearer {}".format(r['access_token'])
  }
  user = requests.get("https://discordapp.com/api/users/@me",headers=headers).json()
  headers = {
    'Authorization' : f'Bot {config["discord"]["dicordAuthBearer"]}',
    'User-Agent' : config["discord"]["discordUserAgent"],
    'Content-Type' : 'application/json'
  }
  data = {
    "access_token" : r['access_token']
  }
  joinGuild = requests.put("https://discordapp.com/api/v6/guilds/{guildID}/members/{userID}".format(guildID=config['discord']['verifiedRoleGuildID'],userID=user['id']),headers=headers,json=data)
  #Redirect user to custom generated faceit url
  try:
    jwtToken = jwt.decode(stateToken, public_key, algorithms=['RS256'])
  except:
    return jsonify({"error":"Unable to verify state token received from discord.com. It was probably altered."})
  # check if discord already registered
  mydb, mycursor = getDbInstance()
  sql = "SELECT discord FROM users WHERE discord = '{}'".format(user['id'])
  mycursor.execute(sql)
  myresult = mycursor.fetchall()
  if user['id'] not in str(myresult):
    encryptedToken = jwt.encode({**user,**jwtToken}, private_key, algorithm='RS256').decode("utf-8")
    return redirect(f"https://accounts.faceit.com/accounts?response_type=code&client_id={config['discord']['discordClientID']}&redirect_popup=true&state={encryptedToken}", code=302)
  else:
    return redirect(f"https://{config['app']['domain']}/warface?error=discordalreadyregistered", code=302)

@api.route("/warface", methods=['GET'])
def warface():
  errorCode = request.args.get('error', default="")
  if errorCode.lower() == "notfound":
    return render_template('index.html', error=True, info="Warface nickname does not exist")
  elif errorCode.lower() == "inactive":
    return render_template('index.html', error=True, info="Inactive Warface player. Login ingame before verifying your Faceit Account.")
  elif errorCode.lower() == "wfalreadyregistered":
    return render_template('index.html', error=True, info="This Warface username is already bound to another user. Contact a Faceit Admin.")
  elif errorCode.lower() == "discordalreadyregistered":
    return render_template('index.html', error=True, info="This Discord ID is already bound to another user. Contact a Faceit Admin.")
  elif errorCode.lower() == "faceitalreadyregistered":
    return render_template('index.html', error=True, info="This Faceit Account is already bound to another user. Contact a Faceit Admin.")
  elif errorCode.lower() == "useroffline":
    return render_template('index.html', error=True, info="User must be online in-game to continue with the verification process.")
  elif errorCode.lower() == "faceithubs":
    return render_template('index.html', hubs=True)
  return render_template('index.html')

@api.route("/logout", methods=['GET'])
def logout():
  session.clear()
  return redirect(url_for("warface"), code=302)

@api.route("/discordCallbackProfile", methods=['GET','POST'])
def profileCallback():
  authCode = request.args.get('code', default="")
  stateToken = request.args.get('state', default="")
  data = {
    "grant_type" : "authorization_code",
    "client_id" : config['discord']['discordClientID'],
    "client_secret" : config['discord']['discordClientSecret'],
    "redirect_uri" : f"https://{config['app']['domain']}/discordCallbackProfile",
    "code" : authCode
  }
  headers = {
    "Content-Type" : "application/x-www-form-urlencoded"
  }
  r = requests.post("https://discordapp.com/api/oauth2/token",data=data).json()
  if not 'access_token' in r:
    return jsonify({"error":"Discord authorization failed. Retry."})
  headers = {
    "Authorization" : "Bearer {}".format(r['access_token'])
  }
  user = requests.get("https://discordapp.com/api/users/@me",headers=headers).json()
  session['discordID'] = user['id']
  session['discordUser'] = user['username']
  return redirect(url_for('profile'))
  
@api.route("/profile", methods=['GET'])
def profile():
  if not 'discordID' in session:
    return redirect(f"https://discord.com/api/oauth2/authorize?client_id={config['discord']['discordClientID']}&redirect_uri=https%3A%2F%2F{config['app']['domain']}%2FdiscordCallbackProfile&response_type=code&scope=identify", code=302)
  
  userData = getDbUserFromDiscordID(session['discordID'])
  if not userData:
    return render_template('profile.html', error=True, info=f"{session['discordUser']} does not appear to be a verified user. Contact a Faceit Admin.")
    
  data = {
    'game': {
      'wfnickname': userData['game'],
      'lastregdate': userData['reg_date'],
      'lastregtimestamp' : int(userData['reg_date'].timestamp())
    },
    'discord': {
      'username': session['discordUser'],
      'id': session['discordID']
    },
    'faceit' : {
      'nickname': userData['faceit_name'],
      'guid': userData['faceit']
    }
  }
  session['warfaceGameID'] = userData['csid']
  session['nextGameChangeAvailable'] = data['game']['lastregtimestamp'] + 2592000 # +30days
  return render_template('profile.html', data=data)

@api.route("/profileGameAccount", methods=['POST'])
def profileGameAccount():
  if not 'discordID' in session:
    return redirect(f"https://discord.com/api/oauth2/authorize?client_id={config['discord']['discordClientID']}&redirect_uri=https%3A%2F%2F{config['app']['domain']}%2FdiscordCallbackProfile&response_type=code&scope=identify", code=302)
  
  if datetime.now().timestamp() < session['nextGameChangeAvailable']:
    return jsonify({"status":"error", "message":"Game name change is available only once every 30 days. Next change available after: {}".format(datetime.fromtimestamp(session['nextGameChangeAvailable']))})
  
  if request.headers.getlist("X-Forwarded-For"):
    ip = request.headers.getlist("X-Forwarded-For")[0].split(",")[0]
  else:
    ip = request.remote_addr
  
  nickname = request.json['nickname']
  previousCSID = session['warfaceGameID']
  
  r = requests.get(f"https://api.wfstats.cf/playerInfo?server=int&nickname={nickname}").json()
  if 'status' in r and r['status'] == 'error':
    return jsonify({"status":"error", "message":"User must be online in-game to continue with the verification process."})
  nickname = r['nickname']
  csid = r['online_id']
  
  mydb, mycursor = getDbInstance()
  sql = "SELECT game FROM users WHERE game = '{}'".format(nickname)
  mycursor.execute(sql)
  myresult = mycursor.fetchall()
  if nickname not in str(myresult):
    userData = getDbUserFromDiscordID(session['discordID'])
    sql = "UPDATE users SET game = '{}', csid = '{}', ip = '{}' WHERE discord = '{}'".format(nickname,csid,ip,session['discordID'])
    mycursor.execute(sql)
    mydb.commit()
    if csid != previousCSID and config['discordWebhookNameChanges'] != "":
      embed = {
        "username": "Faceit Verifbot",
        "embeds": [
          {
            "title": "Verified User changed game account",
            "description": f"New nickname:  `{nickname}`  \nOld nickname: `{userData['game']}`\nCSID does not match: `{previousCSID}` -> `{csid}`",
            "color": 125
          }
        ]
      }
      requests.post(config['discordWebhookNameChanges'],json=embed)
    session['warfaceGameID'] = csid
    setDiscordRoleAndName(session['discordID'], f"{userData['faceit_name']} | {nickname}")
    return jsonify({"status":"success", "message":"Warface account was bound to this discord user."})
  else:
    return jsonify({"status":"error", "message":"This Warface username is already bound to another user. Contact a Faceit Admin."})

@api.route("/profileFaceitAccount", methods=['POST'])
def profileFaceitAccount():
  if not 'discordID' in session:
    return redirect(f"https://discord.com/api/oauth2/authorize?client_id={config['discord']['discordClientID']}&redirect_uri=https%3A%2F%2F{config['app']['domain']}%2FdiscordCallbackProfile&response_type=code&scope=identify", code=302)
    
  userData = getDbUserFromDiscordID(session['discordID'])
  headers = {
    "Authorization": f"Bearer {config['faceitTokens']['faceitDataAPIKey']}"
  }
  r = requests.get(f"https://open.faceit.com/data/v4/players/{userData['faceit']}", headers=headers).json()
  faceitNick = r['nickname']
  mydb, mycursor = getDbInstance()
  sql = "UPDATE users SET faceit_name = '{}' WHERE discord = '{}'".format(faceitNick,session['discordID'])
  mycursor.execute(sql)
  mydb.commit()
  setDiscordRoleAndName(session['discordID'], f"{faceitNick} | {userData['game']}")
  return jsonify({"status":"success", "message":"Faceit nickname was refreshed", "nick": faceitNick })

@api.route("/completed", methods=['GET'])
def completed():
  state = request.args.get('state', default="")
  
  try:
    jwtToken = jwt.decode(state, public_key, algorithms=['RS256'])
  except:
    return redirect(f"https://{config['app']['domain']}/warface", code=302)
  
  return render_template('completed.html',discord=jwtToken['discord'],faceit=jwtToken['faceit'])

@api.route("/nickCheck", methods=['POST'])
def nickCheck():
  try:
    nickname = request.form['nickname']
  except:
    return jsonify({"error":"Method not allowed"})
  r = requests.get(f"https://api.wfstats.cf/playerInfo?server=int&nickname={nickname}").json()
  if 'status' in r and r['status'] == 'error':
    return redirect(f"https://{config['app']['domain']}/warface?error=useroffline", code=302)
  else:
    nickname = r['nickname']
    csid = r['online_id']
  mydb, mycursor = getDbInstance()
  sql = "SELECT game FROM users WHERE game = '{}'".format(nickname)
  mycursor.execute(sql)
  myresult = mycursor.fetchall()
  if nickname not in str(myresult):
    encryptedToken = jwt.encode({"wfnickname":nickname,"wfcsid":csid}, private_key, algorithm='RS256').decode("utf-8")
    return redirect(f"https://discord.com/api/oauth2/authorize?client_id={config['discord']['discordClientID']}&redirect_uri=https%3A%2F%2F{config['app']['domain']}%2FdiscordCallback&response_type=code&scope=identify%20guilds.join&state={encryptedToken}", code=302)
  else:
    return redirect(f"https://{config['app']['domain']}/warface?error=wfalreadyregistered", code=302)

@api.route("/", methods=["GET","POST"])
def default():
  return jsonify({"error":"Method not allowed"})

@api.errorhandler(403)
def page_forbidden(e):
  return render_template('403.html'), 403

@api.errorhandler(404)
def page_not_found(e):
  return render_template('404.html'), 404

@api.errorhandler(500)
def page_not_found(e):
  return render_template('500.html'), 500

if __name__ == '__main__':
  api.run(port=config['app']['port'], debug=False)
