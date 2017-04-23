#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <stdlib.h>
#include <windows.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);

	char* RSA_encrypt(char *str);

	char* RSA_decrypt(char *det);

    ~MainWindow();

private:
    Ui::MainWindow *ui;
	/*RSA	 	 		*r;
	int  	 	 	bits;
	unsigned long	e;
	BIGNUM 	 	 	*bne;
	BYTE			*p;*/

private slots:
    void decode();
    void encode();
};

#endif // MAINWINDOW_H
