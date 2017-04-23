
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include <QPlainTextEdit>
#include <QTextStream>

#include <iostream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl\pem.h>


#include "utils.h"
//#include "CChineseCode.h"


using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{

	ui->setupUi(this);

	QFile keyFile("key.pem");
	QFile pubFile("pubkey.pem");
	
	if (!keyFile.exists()){
		system("openssl genrsa -out key.pem 1024");
	}
	else{
		if (!pubFile.exists()){
			system("openssl rsa -in key.pem -pubout -out pubkey.pem");
		}
	}
	QString line;
	if (!keyFile.open(QIODevice::ReadOnly | QIODevice::Text)){
		return;
	}
	QTextStream in1(&keyFile);
	while (!in1.atEnd()) {
		line += in1.readLine();
	}
	ui->privateKey->setPlainText(line);

	line = "";
	keyFile.close();


	if (!pubFile.open(QIODevice::ReadOnly | QIODevice::Text)){
		return;
	}
	
	QTextStream in2(&pubFile);
	while (!in2.atEnd()) {
		line += in2.readLine();
	}

	pubFile.close();
	ui->publicKey->setPlainText(line);

    //    加密信号和槽
    connect(ui->btn_encode,SIGNAL(clicked()),this,SLOT(encode()));

    //    解密信号和槽
    connect ( ui->btn_decode,SIGNAL(clicked()),this,SLOT(decode()));

}

//解密
void MainWindow::decode(){

    //获取密文
    QString encode = ui->te_dist->toPlainText ();
	
	//string str = HexToBin(encode.toStdString());

	string str = base64_decode(encode.toStdString());
	
	const char *ch = str.data();

    //    解密。。。
	char *det = RSA_decrypt((char *)ch);

	printf("%s", det);

	//string s = BinToHex(string(det));

    //设置原文

	encode = QString::fromLocal8Bit(det);
	//encode = QString::fromStdString(pstr);

	ui->te_source->setPlainText(encode);

	free(det);
}

//加密
void MainWindow::encode(){
    //    获取原文
    QString source = ui->te_source->toPlainText ();


	QByteArray byte = source.toLocal8Bit();

	char * chs = (char *)(string(byte)).c_str();

	printf("%s", chs);

	/*string str = qstr2str(source);

	printf("%s", str.c_str());

	char *chs = (char *)str.c_str();*/
		 
	
	/*string pstr;
	CChineseCode::GB2312ToUTF_8(pstr,chs,strlen(chs));*/


    //    加密。。。
	char *det = RSA_encrypt(chs);

	//bin2str((unsigned char*)det, chs, strlen(det), 16);

    //    设置密文
	string base64;

	base64 = base64_encode((const unsigned char *)det, strlen(det));

	//string s = BinToHex(string(det));
	//bin2str((unsigned char*)det, str, strlen(det), 16);

	//设置原文
	//source = QString::fromLocal8Bit(det);
	//source = QString::fromStdString(base64);

    ui->te_dist->setPlainText (str2qstr(base64));

	free(det);
}

char* MainWindow::RSA_encrypt(char *str){

	char *p_en;
	RSA *p_rsa;
	FILE *file;
	int flen, rsa_len;

	if ((file = fopen("pubkey.pem", "r")) == NULL){
		cout << "open public key file error";
		return NULL;
	}

	if ((p_rsa = PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
		cout << "read public key pem to create RSA error";
		return NULL;
	}

	flen = strlen(str);

	rsa_len = RSA_size(p_rsa);

	p_en = (char *)malloc(rsa_len + 1);

	memset(p_en, 0, rsa_len + 1);

	if (RSA_public_encrypt(rsa_len, (unsigned char*)str, (unsigned char*)p_en, p_rsa, RSA_NO_PADDING) < 0){
		cout << "encrypt error!";
		return NULL;
	}
	RSA_free(p_rsa);

	return p_en;
}

char* MainWindow::RSA_decrypt(char *str){
	char *p_de;
	RSA *p_rsa;
	FILE *file;
	int rsa_len;
	if ((file = fopen("key.pem", "r")) == NULL){
		cout <<"open key file error";
        return NULL;	
	}
	if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL){
		cout << "set RSA private key error";
	    return NULL;
	}
	rsa_len = RSA_size(p_rsa);
    p_de = (char *)malloc(rsa_len + 1);
	memset(p_de, 0, rsa_len + 1);

    if (RSA_private_decrypt(rsa_len, (unsigned char *)str, (unsigned char*)p_de, p_rsa, RSA_NO_PADDING)<0){
		return NULL;
	}
    RSA_free(p_rsa);
	fclose(file);
	return p_de;
}


MainWindow::~MainWindow()
{
    delete ui;
	//RSA_free(r);
}
