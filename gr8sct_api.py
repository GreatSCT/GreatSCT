#!/usr/bin/env python
from fileOps import FileOps
from generator import Generator
from flask import Flask
from flask_restful import reqparse, abort, Api, Resource

app = Flask(__name__)
api = Api(app)
generator = Generator()
parser = reqparse.RequestParser()
parser.add_argument('config')

class Config(Resource):
    def get(self):
        try:
            configDir = './config/'
            fileOps = FileOps(configDir)
            configs = { "configs" : fileOps.getConfigs() }

        except:
            abort(404, message="Config does not exist.")

        return configs

class Template(Resource):
    def get(self):
        try:
            configDir = './template/'
            fileOps = FileOps(configDir)
            templates = { "templates" : fileOps.getConfigs() }

        except:
            abort(404, message="Config does not exist.")

        return templates

class Generate(Resource):
    def post(self):
        try:
            args = parser.parse_args()
            configDir = './config/'
            fileOps = FileOps(configDir)
            fileOps.loadConfig(args["config"])
            current = fileOps.getCurrentConfig()
            payload_name = current["Output"]["var"]
            execution = current["Type"]["runInfo"]

            with open(payload_name, 'r') as f:
                payload = f.read()

            payload = { "payload" : payload, "execution" : execution }

        except:
            abort(404, message="Config does not exist.")

        return payload

api.add_resource(Config, '/config')
api.add_resource(Template, '/template')
api.add_resource(Generate, '/generate')

if __name__ == '__main__':
    app.run(debug=True)