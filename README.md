# Detector de Rootkit em Espaço de Usuário (Usermode)

Este projeto foi criado para inspecionar e comparar as seções de memória do NTDLL de processos em execução com a versão em disco de `ntdll.dll` em sistemas Windows. Seu objetivo principal é detectar possíveis modificações indicativas de rootkits em modo usuário. Como a única forma confiável de um rootkit em modo usuário manter persistência é hookando `NtResumeThread` (ou funções vizinhas durante a criação de threads), verificar a integridade do `ntdll` é uma maneira viável de observar a presença de um rootkit. Outros métodos de persistência incluem patching da tabela de importação; entretanto, isso não é confiável, visto que o `ntdll` não possui uma tabela de importação, deixando a seção `.text` como o único candidato para hooks em usermode.

## ✨ Funcionalidades

* Analisa o `ntdll.dll` diretamente do disco para recuperar a seção `.text`.
* Analisa a seção `.text` do `ntdll.dll` carregado na memória de cada processo em execução.
* Compara essas seções para identificar discrepâncias.
* Suporta processos **wow64** e **64-bit**.
* Fornece um resumo dos processos potencialmente patchados, auxiliando na detecção de rootkits em modo usuário.

## 🧰 Requisitos

* Sistema operacional Windows.
* (Opcional) Privilégios de administrador para inspeção da memória dos processos.


## 📝 Observações

* Testado contra rootkits em modo usuário publicamente disponíveis:

  * [r77-bytecode](https://bytecode77.com/) 🔍

---

**Nota:** Este projeto é voltado para fins de análise de segurança e pesquisa. Utilize-o de forma ética e em ambientes controlados (máquinas de laboratório, VMs isoladas, etc.). ⚖️

---

## 💌 Contato

**Caso queira me contatar ou precise de algum serviço, me encontre nas seguintes plataformas:**

**Usuário do Discord: 4wj.**

**Instagram: @glowwz9**

**E-mail: vliyanie1337@proton.me**

