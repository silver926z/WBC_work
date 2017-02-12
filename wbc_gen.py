import argparse
import os, subprocess
import sys
import re
import fileinput

def parseArgument():
	parser = argparse.ArgumentParser(description='Android APK Encryption/Decryption Library')
	parser.add_argument("-k16", "--key16", help="AES key (16-byte string)", type=str, required=True)
	parser.add_argument("-k24", "--key24", help="AES key (24-byte string)", type=str, required=True)
	parser.add_argument("-k32", "--key32", help="AES key (32-byte string)", type=str, required=True)
	parser.add_argument("-iv", "--IV", help="AES IV (16 or less bytes string)", type=str, required=True)
	args = parser.parse_args()
	return args
	
args = parseArgument()

import random
import string

keys = "7c4626e600a719f7406fc8bb80a721fb6bfca4527f67c00935f967d4167c15eeb9bcaee03431459c0e5ae9a98f7bac99a6f03d5799245dc60424f9271d54522305c687aa23bdce9f4f99ad401182ddba0ab2374362a931dd579cd5547f12a2fd76544e18d5da0c6bf1501721026d8c509f453ad6324ae19f55efcee26b555c16decc3c9135877370ff69e39401ab3fea643780c62885c1530a7994d671bc3f1d"
keys_240 = "c6c63a50dd1ea28562d895dc226ea6bc319657aa6f61432117b06995a077c38294966b1f80867de8c6f11658a622365054342090fe1b8c85129f161b92941495a7cab3a118657f1b8ab2ddb823cb42a2492a60e1f02133568e6433f15b99184431a5ca17f0cb5931b4b7fdb85b3d20a7f831f88d38dd9dbade9bf24d202af4234e1155467cb1ad90c966479062e44fab7161e46fb09299e86b97a38310c6c9f470db6b4d1e4b616780efd5573dfc6cc14fa4f7e7b32a70a07b493989d468a65625f9211ca05086aa72536cd1c4a4c2641429fe3ac37a60f0b0574c498ee049bec4634c3bcd456f9bdeee5a1cd2392cbf"
keys_320 = "e4607b591740a85d82a178a06a241ed6d02deeb170513cf5f471b680a18eea48ab89f4d52d5f2a86dc668d9bdff6918b71b9adb27fc74a80a8f472e84360516640d5bc107ddcdcb4a81f5fe570af1c72ef2040d068ffb167fe7017fd839c3f47b8c04ef0c0cab71f8db17d1571f98f359b4a6da6e924f95927aeb2f1bf513e13f5fc6fd984f0e0e14dc6cb703246eb401570ba37816c323c5cbd1cd092f98bffe8861d9030cb5f6248f14439c3bac079feac1065c56a29dfbd8677cab9bbc0f787b5133ec1b7309ebc541b1b10448657f13460c4e9a3a7aa90c89cc349a584efeaee8ea0dffb75f6e941a748aee0498e6caf7b70e0d22a5ea1afe479db14f6d99e74dd1dbb3a456046ed3a7fe2542f72858937d3e09e66ecd0101619291bcbe5e5be1be12ae7e97a5cb1a3de3d6594409b89b028b0eddc5c35a813451d9284c2"
keys_4wEnQ = "8c8ee17a80af908498c89e654d79ecad9f20f059c04120e1532030b175df2245b957d073ac8ac9c2c59fb75480a14c30e82933c9a7fcd0982e5893b3de52deffad6062cc9df4fee7b0f9b0654dd0eb2d56964b34f3f66b92a0b719d717ac1ea3ea1e40c9c685f070a51c25ea2a63b530c43ff881d3269d89bf6a6547e979dc5ec19d85f1e1fe623ec435eed8741c1eaf8399f7102e636b6f5f5169f04894375de9b593275ce37ca99978bf2771f49083a1b5e9558ad8cfcc59b69c23f53dfdd88c2917277bab64cee7589919b5e35e802a7a77b9a65098117d54f08367ab541653f3e520f0b62e5b62fb35bcd81feed09e2b9e26c2c4957832e3cf4950cf7a775ffee72fb077a4199124f0a1fc6e361ac03a20e5e031148c743410805a7b4965795ab9f7e8a31c8b18bf892d8645b16a53754b21c0b5a5d4dbe8362fb96516e4"
keys_snLlx = "3539c755f0434522c0aad05568baaaca201fbece1f8230569fd32e73ca3fdeca93c07087a4c681f115c845c8a89c7b64001b3c4ab5862c2e77f940d73611f0cef031f29ebb7dab5d2873b9105fd1777e41975630eaf06973c72054e3b7587ba187d0306c51213fba15d424f0144661bf69f88ab076dee3f03ab57c8a2d8c5c3fd877f73e7a7c60a999bb6a457644ae6edb608016bdbd2b27de8e43403aefcfa6367610d37218c0479819a6b07900cd15eef5ffbca04d8715e3504cc89e53a7e933fad2562aff7ac576f0a328c92aaef95f00393be15be9b0b4f9f0e99c2c4d65c0fdc0e987e267bc10ec25d9e1898e7a85d757e0e447a571d7fee09f7184c4a83ab2a442b0f12688d253bb783711457228623333d6207ee03afc3aefa9909d5e88fd733032dde461e6cb172cd5de3828ddf24d6a5f587112ef97a77193146559"
keys_h5WUQ = "194b95783e22b5b06dbe979c71cd2881242432621a1198548dc5bc33508dceb0943c17a1fecae16df2a57648942d3af43ad89e2f907f2661b0f960b5bd1c206d2c2b58fa658e3a318fc1760032b561c7f43e3731473b9467f260bb55a0285a3b8c41e91bc6509ccfb8c8d410702a1836eab76d2f5d391a8b117f9929859ba2bbc7a332189a5476c5fb3823b4dc78aa6e9eef62cfb41160b08b4037e8e3b7f0a47b775cea1a29b43ed0b03971e0b78bf54edfde2350808bbc6ec7a8e26e7e9873d8f42083f01f4855e12832cb25141638c3ebe13bf360cddefdb2c373661818399be1381844989d232ab9494900d86057db9db875c15aa09883da6756773910247d7ec766d8d3c5f0faf7674cdd773ca71fadcee34ebb5ad088772bf918b05d2d28973d5898d0fec3883c57e71bf2b366beda3ccd0056ae15935bb18e742ce868"
keys_7edM8 = "4cf133e9e1cdc8c7d45e2773be95273ecde6709b1a664650167787f0ebbcb61c4bc32131b69ba0e920ed6862b0b513f0ffa0bc9a895d34e46f8483e073eec1389f8442737193727360bb7d1c3a90e92d3ecdc9898f2f8ae09f7aa7287e312b38ea9726ffcd71fd97a8af60fc808c5617556023223826e87964e35a5096f4fc5b4991647fd51977d331278b3200d56da56fcb3e72a461572ce664a17e8ca4783fc725cf3c902ac3b68c7ebe3491de11d75662a86d153de972ac2e23602c5f12346089d0a9841be0bf4738fd86d35339e090cf9cf7aac03855ce70feed49a2bde863e8903b5847e1afc8f48a6593a77733bda4b0cc615da729c660d1da64d58dc0a57bfe46b8557f3eb6ba2094b710bd5f1ce64cf5e3f3218058d473584ae23c5dc850c9875616b77bedc64da492e061daf3e041e13b723ea9119739b65e1792e2"
keys_bnDyW = "ce394c1fae272df12be76e15d01a1b6ce83079a6905240d2c07d3eefdc3942e8d79eaca1c69ccb1d8ff0b5706ae77596fdad365c6b8785c0729d79932c9341c590d850e29d26dbba697a821f15a952fa90f165341ae7db7034fc5db4cf6d985aa55e47116338408340d5fc2e81f6cd54f87090bf4d31ac838f41f47766ee9892c0537e1b9792ddb9b0d380b34258fafc5939b3657488b44a3cbdcffc80eb534d8b4bdef2d4dd1aa6e97f99b058f9194395d27446ade826bd1823ead9c37e2af51e2d1d5bb3a5b0b66b22896fb8252fe100d068ffb0d97447d28f7520ece6421e2dcc87925612739fa878a589e614f43db791a230b3ae8fc640bd47548bf6784d90ad2fe7b39c4a39c0b84c6042524fa5796475724c62f0dae074a23352e171f3b739cf34e6b68b37e38014c0a7ec14f0ca1f9ae399d0b7177057f7d8b1c240cc"
keys_DBbx5 = "d575ddfbba5d5f3419a8cac35bae50fe6b4cb8936bdcc86ad75a78008c88f5e062939e698631ed42cc111b27a312f0e495a2289f224f1e52bcee5f20a24cc55560d0e4e16db85c93854480a4f5b6f5699c31e0c0d563eb2cae504aa0ace17ea02adde23f59463412212f99e28f9232ef3156897bdfdbd7e4c0f266de5548752e72df49a19aec819c252eae4b4b18426c24b18fdc80a3f181904e6ffc9c8e2d79f23fd140da52c91260aec798c4fc8af3b8a9c32148bfddecda48281358a38c3890e75654df3d5ea3d65ab1578a8fc7d1aec440bb6a527038abfba451c079916c88c39cb0af1d10bbe33722522027a529ba939fd5d6b8f7cff23ad430e56a1e9522b28682b8c3805c2d143879a567c05815d2ff80a5f988962deb455ac2a65ce3d1c76d4d1a9da8d07d58f1f82efa4782b07d2a44219b15c92749d0a394ae48fa"
keys_S9gOs = "4f6e8c305d58b7ebd61b7b4cfeb08d9a391da6c8404191ebec40d76ac3c4a3ead5dd26e9306ce6ada5fe867a1a701889af8935b3e07f92d7be2deb8b00699460f9d06cdb9b93e11f8f8026e0a9f3cbe1c23cbdd690ec2693631f7b7a11763964139abf5f40296b54fc5a5980c8888e9b8cf6afbfa8a33630399ba89bfae25265ff598f2ef39ce27f4dc413b66e899a39f8ffd464265b1963e553c094103ac1a4e3115c3ca4fe3cf3d0d63fc8a8c38013a0fab4ce7ac6aaa51f58d082d728d233316138374a61375cbc63748751f34092f0d7e16d994e9485aad88339cbba3b6e8b912ddc7759c31c60abfe1388838a6efba8c8cb2bd30010b0d08e11fce9b825514c1f64d370f09c46b9ac1224961b40f796e1da6e5ffcb5d67e75a86625153c1d20da2f586c53e3c6a3728b1d7c454ee7cbdbd363c3cd2c6e182016837c52a6"
keys_qWlbK = "35aa3f9c8bfef136202f86659ca01512404590af609a351b3c3c2253fde047994df68a79e450475f527e7d5d6ac2bf5043589c77b4b7add610ae622ca1a84732aa2741bd5088fd5ac8fb2e9f75533a12ef3c74a88283e7c14f4650134f204bbd509847481b5d9f3ef4bbf0ca578a48bbae8bcfbd8dde55dd9c11c9891d4ac0c49d9ddafdf1cac86cb5a332169ed6f873ccd7cb90e41a16a757a74f29374e29207dc41769591bf9e667727e4ac0304ae0bd353ec0f816d3d7a29c37636987f9422a60fd4e141e3074fd2c384f7000cfb26915c0b8d1b5cfd110ca7b242a403e10304062f25d2da676fb002fca9cf7ed51905115dd94d6adf881a175896c188760d5158f70d42f6f3af01ec1aaccf992fc18b0e877d2503ca2438499ebe354a72bc0c252a9c1634e3044a5e221d4a314508b54b34f547dcbba886fd45577f7ff26"
keys_aYcnz = "a6fcf8d4468db4b3c6908f475725e5d71a1a5ee4f82e1d5ea15160fe7aab63b069eef1719af286c05b2c273db3abb02e62b2f36d785e167cb7f1b188c9ce67a6c563c3653889d35844785dbac456f06217bdc14ab71ee76448aec3e6bccce89b745840201ef39a163395ecc37d10901592e4e853c021fe3d68fad28634af9d9321542a1ca12d26fcd1e5f7947ced19461bf8a99f6b334124738c84d217aed51ea690b7be3fb8143f1f30ead291f7b99b356ac41e3a2d2f43a52be947929477625ef7e6bccfc7d446eea67fb6dbe9d6eed8e2c533a2e1e463b16753a3774b4fa0756c213828d0cca1b16aaa241623f61b582ae8d1575c41e63749cfed5040bf9a007b9230ac273b58409340db43cf43411159d27e8cac87b98c19f1a01cc26ee910a676383d2d2a5ad89c70e8e71cc88d99aeda135da3c2b08a79e0c06c3f3636"
keys_te8Gl = "3d15af111fbfa51c109b1680e1aba177f9b04d2f9f50869710c770dcb0854c2dffb8af6587e2cebe8a14c1b07ce2bbdb104e478f8f6d3dfeddb68d6dbd7ba8218a4a1f2f51f5c9368af262d0b15290c913f2fd48e05280972ed64eb980e05092585d29a87cca75f833d3e540318771202d3d705bfdc0412d2744d2c69545ce431fa148ae461ecb7b4f9f5867966ffef1eb63b453c0defdb2b895a4104085a915b4eac0a8f897ae6f7ec2648b767f80d5e5213bbe6d4ad0a0d2b2b971acc8e5435fb5db1337a08b59ddd6db56e08763b8ca3c3b7a513d7f6f55519ab4c32f33572ddd876c69415a697f732f9469d1dc15c271e88fb61f9ec3757efd262caddf592389bd7ca9c014b84fb0f35b8f202613634fdb2ef72d2920dee2ba654ad8d8889ed18fe4e0c06e4eb3f841186d5c80c8dc43a38338a0b61c817d4c20349bef24"
IV = "0123456789012345"
appName = "APPpppppppppName"
BundleIdentifier = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

def wbc_gen_key(real_key):
	original_key = real_key
	#### step 1. gen 9 random keys
	keys = []
	for x in range(0,9):
		k = [random.randint(0,255) for n in xrange(len(original_key))]
		keys.append(k)
	K10 = [ord(x) for x in original_key]
	#print keys
	#print K10
	#### step 2. xor the 9 random keys with the original_key
	for key in keys:
		tmp = []
		for x in range(len(K10)):
			tmp.append(K10[x]^key[x])
		K10 = tmp
		
	#print "K10" , K10
	#### step 3. append the xor-ed key to the keys (the 10-th key in keys)
	keys.append(K10)
	
	#### step 4. [int] to [hex] to hexStr+hexStr....+hexStr
	outs = []
	for key in keys:
		outs.append("".join([ '%02x'%x for x in key]))
	return outs

if args.key16 and args.IV and args.key24 and args.key32:
	if len(args.key16) != 16:
		print "ERROR | KEY must be a 16-byte string"
		sys.exit(0)
	if len(args.key24) != 24:
		print "ERROR | KEY must be a 24-byte string"
		sys.exit(0)
	if len(args.key32) != 32:
		print "ERROR | KEY must be a 32-byte string"
		sys.exit(0)		
	if len(args.IV) > 16:
		print "ERROR | IV length must be less than 16 bytes"
		sys.exit(0)
	outs16 = wbc_gen_key(args.key16)
	outs24 = wbc_gen_key(args.key24)
	outs32 = wbc_gen_key(args.key32)
	#print outs
	
	PATCHED_KEY16 = "".join(outs16)
	PATCHED_KEY24 = "".join(outs24)
	PATCHED_KEY32 = "".join(outs32)
	#print PATCHED_KEY
	
	PATCHED_IV = args.IV.ljust(16 , '0')
	PATCHED_ID = "com.firstbank.mbank".ljust(64 , '0')  # you have to use com.bank as your BUNDLE ID
	
	#### step 5. patch hexStrings and IV to Framework file
	with open('CryptoSwift.framework/CryptoSwift' , 'rb') as file:
		data = file.read() 
		KEY_ADDR = data.find(keys)
		IV_ADDR = data.find(IV)
		keys_240_ADDR = data.find(keys_240)
		keys_320_ADDR = data.find(keys_320)
		keys_4wEnQ_ADDR = data.find(keys_4wEnQ)
		keys_7edM8_ADDR = data.find(keys_7edM8)
		keys_aYcnz_ADDR = data.find(keys_aYcnz)
		keys_bnDyW_ADDR = data.find(keys_bnDyW)
		keys_DBbx5_ADDR = data.find(keys_DBbx5)
		keys_h5WUQ_ADDR = data.find(keys_h5WUQ)
		keys_qWlbK_ADDR = data.find(keys_qWlbK)
		keys_S9gOs_ADDR = data.find(keys_S9gOs)
		keys_snLlx_ADDR = data.find(keys_snLlx)
		keys_te8Gl_ADDR = data.find(keys_te8Gl)
		BUNDLE_ID_ADDR = data.find(BundleIdentifier)
		# print keys_7edM8_ADDR,keys_aYcnz_ADDR,keys_bnDyW_ADDR,keys_DBbx5_ADDR,keys_h5WUQ_ADDR,keys_qWlbK_ADDR,keys_S9gOs_ADDR,keys_snLlx_ADDR,keys_te8Gl_ADDR
	
	file = open('CryptoSwift.framework/CryptoSwift' , 'rb').read()
	patchedfile = ""
	patchedfile = file[0:KEY_ADDR] + PATCHED_KEY16 + file[KEY_ADDR+320:]     
	patchedfile = patchedfile[0:keys_240_ADDR] + PATCHED_KEY24 + patchedfile[keys_240_ADDR+480:]
	patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]
	# ==	
	# patchedfile = patchedfile[0:keys_4wEnQ_ADDR] + PATCHED_KEY32 + patchedfile[keys_4wEnQ_ADDR+640:]	 
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# patchedfile = patchedfile[0:keys_320_ADDR] + PATCHED_KEY32 + patchedfile[keys_320_ADDR+640:]	
	# ==
	patchedfile = patchedfile[0:IV_ADDR] + PATCHED_IV + patchedfile[IV_ADDR+16:]
	patchedfile = patchedfile[0:BUNDLE_ID_ADDR] + PATCHED_ID + patchedfile[BUNDLE_ID_ADDR+64:]
	#print patchedfile[KEY_ADDR:KEY_ADDR+320]
	file = open('./customized_framework/CryptoSwift.framework/CryptoSwift' , 'wb').write(patchedfile)
	
	print "LOG | success, bye~"
else:
	print "ERROR | KEY or IV not found"
	sys.exit(0)
	




