pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Verify Docker') {
            steps {
                sh 'docker --version'
            }
        }

        stage('Build Docker Images') {
            steps {
                sh 'docker compose -f docker/docker-compose.yml build'
            }
        }

        stage('Semgrep Scan') {
            steps {
                sh 'semgrep --config p/python --config p/javascript ${WORKSPACE} --json --output ${WORKSPACE}/security/semgrep/report.json'
            }
        }

        stage('Parse Semgrep Results') {
            steps {
                sh 'python3 ${WORKSPACE}/backend/parser/semgrep_parser.py ${WORKSPACE}/security/semgrep/report.json'
            }
        }
    }
}
