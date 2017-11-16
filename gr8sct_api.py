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
            print(configs)
        except:
            abort(404, message="Config does not exist.")

        return configs

class Template(Resource):
    def get(self):
        # try:
        configDir = './template/'
        fileOps = FileOps(configDir)
        templates = { "templates" : fileOps.getConfigs() }
        print(templates)
        # except:
            # abort(404, message="Config does not exist.")

        return templates

class Generate(Resource):
    def post(self):
        # try:
        args = parser.parse_args()
        configDir = './config/'
        fileOps = FileOps(configDir)
        fileOps.loadConfig(args["config"])
        current = fileOps.getCurrentConfig()
        payload_name = current["Output"]["var"]
        print(payload_name)
        with open(payload_name, 'r') as f:
            payload = f.read()

        payload = { "payload" : payload }

        # except:
            # abort(404, message="Config does not exist.")

        return payload


    # def config(self, config):
    #     try:
    #         configDir = './config/'
    #         with open(config, 'r') as f:
    #             data = config.read()
    #     except:
    #         abort(404, message="Config does not exist.")

    #     config_file = { "config" : data }

    #     return config_file

    # def generate(self, config):
        try:
            fileOps.loadConfig(configs.index(config))
            current = fileOps.getCurrentConfig()
            payload_name = fileOps.selectedConfig(['Output']['var'])
            fileOps.generate(current)

            with open(payload_name, 'r') as f:
                payload = f.read()


            payload = { "payload" : payload }

        except:
            abort(404, message="Config does not exist.")

        return payload

    # def template(self, template):
    #     try:
    #         configDir = './config/'

    #         with open(template, 'r') as f:
    #             data = template.read()

    #         config_file = { "template" : data }
    #     except:
    #         abort(404, message="Config does not exist.")

    #     return config_file

    # def templates(self):
        try:
            templateDir = './template/'
            templates = { "templates" : fileOps.getConfigs(templateDir) }
        except:
            abort(404, message="Config does not exist.")

        return templates

api.add_resource(Config, '/config')
api.add_resource(Template, '/template')
api.add_resource(Generate, '/generate')
# api.add_resource(Config, '/config/<all>')
# api.add_resource(GreatSCT, '/todos/<todo_id>')

if __name__ == '__main__':
    app.run(debug=True)