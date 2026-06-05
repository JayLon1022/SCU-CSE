# 使用官方基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 复制项目代码到容器
COPY ./app /app

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt


# 设置默认启动命令
CMD ["python", "app.py"]
