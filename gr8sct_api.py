#!/usr/bin/env python
from fileOps import FileOps
from generator import Generator
from flask import Flask
from flask_restful import reqparse, abort, Api, Resource

"""
This module is used to for the GreatSCT RESTful API.
"""

app = Flask(__name__)
api = Api(app)
generator = Generator()
parser = reqparse.RequestParser()
parser.add_argument('config')


class Config(Resource):
    """
    This class is used to get configs and return configs.

    :param Resource: flask resource
    :type Resource: Resource
    :returns: configs
    :rtype: dict
    """

    def get(self):
        """
        GET /config

        :returns: templates
        :rtype: dict

         :Example:

        curl http://localhost:5000/config
        """
        try:
            configDir = './config/'
            fileOps = FileOps(configDir)
            configs = {"configs": fileOps.getConfigs()}

        except:
            abort(404, message="Config does not exist.")

        return configs


class Template(Resource):
    """
    This class is used to get templates and return templates.

    :param Resource: flask resource
    :type Resource: Resource
    """

    def get(self):
        """
        GET /template

        :returns: templates
        :rtype: dict

        :Example:

        curl http://localhost:5000/template
        """
        try:
            configDir = './template/'
            fileOps = FileOps(configDir)
            templates = {"templates": fileOps.getConfigs()}

        except:
            abort(404, message="Config does not exist.")

        return templates


class Generate(Resource):
    """
    This class is used to generate payloads from configs.

    :param Resource: flask resource
    :type Resource: Resource
    """

    def post(self):
        """
        POST /generate

        :param config: name of the config
        :type config: string
        :returns: payload
        :rtype: dict

        :Example:

        curl http://localhost:5000/generate -d "config/MSBUILD/msbuild.cfg" -X POST
        """
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

            payload = {"payload": payload, "execution": execution}

        except:
            abort(404, message="Config does not exist.")

        return payload

api.add_resource(Config, '/config')
api.add_resource(Template, '/template')
api.add_resource(Generate, '/generate')

if __name__ == '__main__':
    app.run(debug=True)
