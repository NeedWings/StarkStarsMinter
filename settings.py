RPC = "https://starknet-mainnet.public.blastapi.io" # Нодя, которую будет юзать софт
Provider = "Argent" # Какой провайдер использовать Argent/argent_newest/braavos
cairo_version = 1 # Версия каиро кошельков (См. на главной странице кошелька в сканере)

mint_amount = [4, 6] # Кол-во минтов ОТ и ДО


# Задержки при ошибках, выполнении транзы и между кошами соответственно
# Тоже От и До
ErrorSleepeng = [1, 2]
TaskSleep = [1, 2]
AccountDelay = [1, 2]



#
# Advanced
#
"""
Если не знаете, где брать значения -- отпишите в лс в тг: @NeedWings
"""
useAdvanced = False
class_hash = ""
implementation = ""
selector = ""