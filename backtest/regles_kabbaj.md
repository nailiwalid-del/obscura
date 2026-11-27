# Règles extraites des vidéos de Thami Kabbaj

Source lue (sous-titres automatiques YouTube, extrait d'environ une minute qui commence en cours de phrase) :
https://www.youtube.com/watch?v=e6HGgUc0lYk

## Ce que la vidéo dit (citations)
- « le marché vient se poser à chaque fois sur la zone des 50 % » (du RSI) « parce qu'on a une belle tendance bien définie ».
- Méthode utilisée « depuis 1999 », illustrée dans son livre par des cas : 11 septembre, krach de mars 2000, krach de 2007.
- Elle « marche toujours » car la psychologie humaine et la cyclicité des marchés persistent.

## Ce que la vidéo NE dit PAS (choisi par l'outil dans backtest_v6.py, `k_pull`)
- période du RSI (14 retenu) ; définition de la tendance (Close > MM200 retenu) ;
- déclencheur exact d'entrée (retour du RSI au-dessus de 50 après un contact retenu) ;
- sortie, stop, taille de position, actifs, unité de temps.

## Autres vidéos
Sous-titres refusés par YouTube (« Sign in to confirm you're not a bot ») : pbCkiaAG3vc, 0LvWG5ox-FM, ixnFWPZy6-s, kof5a6cNuvA.

---
## Mise à jour : conférence pbCkiaAG3vc et extrait ixnFWPZy6-s (sous-titres automatiques YouTube)
Conférence : https://www.youtube.com/watch?v=pbCkiaAG3vc  |  Extrait : https://www.youtube.com/watch?v=ixnFWPZy6-s

### Ce qu'il dit explicitement
- Outils : RSI, stochastique, **moyennes mobiles arithmétiques** (pas exponentielles) car suivies par des gérants
  (effet autoréalisateur) ; **MM 20 / 50**, et **100 ou 150** « pour le long terme » ; volumes ; screeners.
- RSI : **zone de neutralité à 50**. Marché haussier = RSI au-dessus, la zone sert de **support** ; baissier = en dessous.
  Un **pullback** après une cassure donne un **point d'entrée** (timing) ; il faut **attendre une confirmation**.
- Divergences haussières/baissières du RSI pour détecter un retournement tôt ; les excès (euphorie / panique) sont les plus profitables.
- Entrer plus tôt « **pas avec une grosse taille, mais avec une taille initiale, puis pourquoi pas renforcer** ».
- Pour chaque configuration : scénario favori + alternative ; miser gros ou rester prudent selon le cas.
- Approche contrariante ; discipline et psychologie ; ne pas trader quand le marché fait du sur-place ; fixer ses niveaux à l'avance.
- « Bougie de contrôle » : outil cité, non expliqué dans cet extrait.

### Ce qu'il ne dit pas (valeurs choisies par l'outil dans `k_pull2`)
période du RSI (14) ; seuil de renfort (Close > MM20 > MM50) ; poids initial (50 %) ; règle de sortie (Close < MM100) ;
stop ; risque par trade ; tout chiffre de taille de position ; définition exacte de la « confirmation ».

### Écarté
- `My6KVgsvGxw` : entretien d'environ 2 h, parcours personnel, aucune règle de trading.
- `C5lRaMqK5SM` : analyse tierce de sa chaîne YouTube, hors sujet.
- Sous-titres refusés par YouTube (bot) : 0LvWG5ox-FM, kof5a6cNuvA, KKdKwCeHAm0, -DFIqXkNiOs. `reWlThik2QY` : pas de sous-titres.
