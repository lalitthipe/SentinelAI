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

        stage('Trivy Scan') {
            steps {
                sh 'trivy fs ${WORKSPACE} --format json --output ${WORKSPACE}/security/trivy/report.json'
            }
        }

        stage('Parse Trivy Results') {
            steps {
                sh 'python3 ${WORKSPACE}/backend/parser/trivy_parser.py ${WORKSPACE}/security/trivy/report.json'
            }
        }

        stage('Gitleaks Scan') {
            steps {
		sh 'gitleaks detect --source ${WORKSPACE} --config ${WORKSPACE}/.gitleaks.toml --report-format json --report-path ${WORKSPACE}/security/gitleaks/report.json --no-git || true'
            }
        }

        stage('Parse Gitleaks Results') {
            steps {
                sh 'python3 ${WORKSPACE}/backend/parser/gitleaks_parser.py ${WORKSPACE}/security/gitleaks/report.json'
            }
        }
	stage('Generate AI Reports') {
            steps {
                withCredentials([string(credentialsId: 'groq-api-key', variable: 'GROQ_API_KEY')]) {
                    sh 'python3 ${WORKSPACE}/backend/ai/generate_reports.py'
                }
            }
        }
    }
}
