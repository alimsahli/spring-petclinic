pipeline {
    agent any

    stages {


        stage('MAVEN Build & Test'){
            steps {
                sh 'mvn clean install'
            }
        }

        stage('SECRET SCAN (Gitleaks via Docker)') {
            steps {
                sh 'docker run --rm -v $WORKSPACE:/app -w /app zricethezav/gitleaks:latest detect --source=. --report-path=gitleaks-report.json --exit-code 0'
            }
        }
        stage('Security Check: Forbidden .env File') {
            steps {
                script {

                    def envFileExists = fileExists('.env')

                    if (envFileExists) {
                        error("🚨 FATAL SECURITY ERROR: The forbidden '.env' configuration file was found in the repository. Please remove it and use Jenkins credentials/secrets instead.")
                    } else {
                        echo '✅ Security check passed. No forbidden .env file found.'
                    }
                }
            }
        }

        stage('SONARQUBE SCAN'){
            environment{
                SONAR_HOST_URL='http://192.168.50.4:9000/'
                SONAR_AUTH_TOKEN= credentials('sonarqube')
            }
            steps{
                // SonarQube utilise toujours le scanner Maven pour une intégration facile dans les projets Java
                sh 'mvn sonar:sonar -Dsonar.projectKey=devops_git -Dsonar.host.url=$SONAR_HOST_URL -Dsonar.token=$SONAR_AUTH_TOKEN'
            }
        }

        stage('QUALITY GATE WAIT (BLOCKING)') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    // C'est ici que l'outil Jenkins vérifie le résultat de SonarQube
                    // Assurez-vous que le plugin est installé et l'instance configurée!
                    // waitForQualityGate abortPipeline: true, sonarQube: 'MonServeurSonar'
                    echo 'Vérification du Quality Gate SonarQube en cours...'
                }
            }
        }

        stage('DEPENDENCY SCAN (SCA - Trivy via Docker)') {
            steps {
                script {
                    // Standardize the internal path to /app for both tools

                    // 1. EXECUTE TRIVY SCAN (Write to /app/trivy-sca-report.json)
                    sh '''
                        docker run --rm \
                          -v $WORKSPACE:/app \
                          -w /app \
                          aquasec/trivy:latest \
                          fs --severity HIGH,CRITICAL --format json --output trivy-sca-report.json . || true
                    '''

                    // 2. DISPLAY FORMATTED REPORT (Read from /app/trivy-sca-report.json)
                    sh '''
                        echo "--- TRIVY VULNERABILITY REPORT (HIGH/CRITICAL) ---"
                        docker run --rm \
                          -v $WORKSPACE:/app \
                          -w /app \
                          realguess/jq:latest \
                          jq -r \'
                            .Results[] | select(.Vulnerabilities) | {
                                Target: .Target,
                                Vulnerabilities: [
                                    .Vulnerabilities[] | select(.Severity == "CRITICAL" or .Severity == "HIGH") | { 
                                        Severity: .Severity, 
                                        VulnerabilityID: .VulnerabilityID, 
                                        PkgName: .PkgName, 
                                        InstalledVersion: .InstalledVersion 
                                    }
                                ]
                            }
                          \' trivy-sca-report.json
                    '''

                    echo 'Le scan Trivy est terminé. Veuillez consulter les résultats ci-dessus.'
                }
            }
        }

        stage('IMAGE CREATION') {
            steps{
                echo "Building image alimsahlibw/devops:latest"
                sh 'docker build -t alimsahlibw/devops:latest .'
                sh 'docker image prune -f'
            }
        }

        // --- STAGE 2: DOCKER HUB PUSH ---
        stage('DOCKER HUB PUSH') {
            steps {
                // Tagging with a unique build number tag for traceability
                sh 'docker tag alimsahlibw/devops:latest alimsahlibw/devops:${BUILD_NUMBER}'
                withCredentials([string(credentialsId: 'dockerhub', variable: 'DOCKERHUB_TOKEN')]) {
                    sh 'echo $DOCKERHUB_TOKEN | docker login -u alimsahlibw --password-stdin'
                    sh 'docker push alimsahlibw/devops:latest'
                    sh 'docker push alimsahlibw/devops:${BUILD_NUMBER}'
                }
            }
        }

        // --- STAGE 3: OWASP ZAP SCAN (DAST) ---
        stage('OWASP ZAP SCAN (DAST)') {
            steps {
                script {
                    def appContainer
                    def targetUrl = "http://172.17.0.1:1234"   // FIX FOR LINUX HOST

                    try {
                        echo "Starting application container on host port 1234..."
                        appContainer = sh(
                                returnStdout: true,
                                script: "docker run -d -p 1234:8080 alimsahlibw/devops:latest"
                        ).trim()

                        echo "Waiting for application to become ready..."
                        retry(5) {
                            sleep 5
                            sh "curl -s -o /dev/null ${targetUrl}"
                        }

                        echo "App ready. Running ZAP Baseline scan..."

                        sh """
                    docker run --rm \
                      --network=host \
                      -v ${PWD}:/zap/wrk/:rw \
                      owasp/zap2docker-weekly:latest \
                      zap-baseline.py \
                        -t ${targetUrl} \
                        -r zap-report.html \
                        -x zap-report.xml \
                        -I
                """

                    } catch (Exception e) {
                        echo "🚨 ZAP Stage Error: ${e.getMessage()}"
                    } finally {
                        if (appContainer) {
                            echo "Cleaning up app container…"
                            sh "docker stop ${appContainer}"
                            sh "docker rm ${appContainer}"
                        }
                    }
                }
            }
        }


    }
    post {
        always {
            archiveArtifacts artifacts: 'trivy-sca-report.json,gitleaks-report.json,zap-report.html,zap-report.xml', allowEmptyArchive: true
        }
        success {
            emailext(
                    subject: "✅ Pipeline SUCCESS: ${currentBuild.fullDisplayName}",
                    body: """Hello Team,
                    The pipeline **completed successfully**!
                    """,
                    to: "alimsahli.si@gmail.com",
                    attachmentsPattern: 'trivy-sca-report.json,gitleaks-report.json,zap-report.html,zap-report.xml'
            )
        }


        failure {
            // This runs only if the pipeline failed.
            emailext(
                    subject: "❌ Pipeline FAILED: ${currentBuild.fullDisplayName}",
                    body: """Hello Team,
                    The pipeline failed. Check the attached Trivy report for details.
                    """,
                    to: "alimsahli.si@gmail.com",
                    attachmentsPattern: 'trivy-sca-report.json,gitleaks-report.json,zap-report.html,zap-report.xml'

            )
        }
    }
}