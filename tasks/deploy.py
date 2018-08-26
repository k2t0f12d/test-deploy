u""" Deploy Cloudformation resources """
from invoke import task
from infra import InfrastructureTemplate


@task
def cfn_up(ctx):
    u""" Task to deploy cloudformation resources """
    infra = InfrastructureTemplate()
    body = infra.generate_template(output='json')
    aws_cmd = 'aws cloudformation ' + \
              'create-stack ' + \
              '--stack-name=test-deploy-stack ' + \
              '--template-body \'' + body + '\''
    print(aws_cmd)
    ctx.run(aws_cmd)


@task
def cfn_down(ctx):
    u""" Task to destroy cloudformation resources """
    aws_cmd = 'aws cloudformation ' + \
              'delete-stack ' + \
              '--stack-name=test-deploy-stack'
    print(aws_cmd)
    ctx.run(aws_cmd)

@task
def cfn_update(ctx):
    u""" Task to update Cloudformation Stack """
    infra = InfrastructureTemplate()
    body = infra.generate_template(output='json')
    aws_cmd = 'aws cloudformation ' + \
              'update-stack ' + \
              '--stack-name=test-deploy-stack ' + \
              '--template-body \'' + body + '\''
    print(aws_cmd)
    ctx.run(aws_cmd)
