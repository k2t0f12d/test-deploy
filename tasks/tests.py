u""" Tasks for running python code tests """
from invoke import task


TestCommand = 'pytest {module}.py --cov={module}'


@task
def test(ctx, module='infra'):
    u""" Run tests checking coverage for local module `infra` """
    ctx.run(TestCommand.format(module=module))
