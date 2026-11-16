pipeline {
  agent any
  options { timestamps(); disableConcurrentBuilds() }
  triggers { cron('H 2 * * *') }   // nightly full run incl. integration
  stages {
    stage('Lint & Unit Test') {
      steps {
        //sh 'cargo fmt --all -- --check'
        sh 'cargo clippy --all-targets || echo "clippy: warnings present (advisory)"'
        sh './run_tests.sh'
      }
    }
    stage('Server Release Build') {
      steps {
        sh 'cargo build --release --bin server'
        sh 'sha256sum target/release/server > server.sha256'
      }
      post {
        success {
          archiveArtifacts artifacts: 'target/release/server,server.sha256',
                           fingerprint: true
        }
      }
    }
    stage('Integration & Pivot') {
      when { anyOf { branch 'main'; triggeredBy 'TimerTrigger' } }
      steps {
        sh './run_tests.sh --integration'
        sh './run_tests.sh --all --pivot'
      }
    }
    stage('Security Audit') {
      steps { sh 'cargo audit' }
    }
  }
}
