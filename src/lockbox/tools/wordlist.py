"""Compact local word list for passphrase generation and dictionary analysis.

Bundled so that passphrase generation works on a machine that has never been
online. It is deliberately small (a few hundred short, unambiguous, easy-to-type
words) to keep the package tiny.

Entropy is always computed from `len(WORDS)` at runtime, never asserted as a
constant, so the strength figures Lockbox reports match the list actually in
use. If you want more entropy per word, point Lockbox at a larger local list
(for example an EFF diceware list you already have on disk) with
`load_external()` -- it reads a plain text file, one word per line, from your
own filesystem. Nothing is ever downloaded.
"""

from __future__ import annotations

import math
import os
from typing import List, Sequence

_RAW = """
able about above acid acre actor adapt add adept admit adobe adopt adult afford
after again agent agile agree ahead aim air alarm album alert algae alien alike
alive alley allow almond alone along alpha also alter amber amble amend among
ample amuse anchor angel anger angle animal ankle annual answer ant apart apex
apple apply april apron arcade arch arctic area arena argue arise arm armor army
aroma array arrow art ash aside ask aspen asset atlas atom attic auction audio
audit august aunt author auto autumn avenue avoid awake award aware away awesome
axis bacon badge bagel baker balance balcony ball balloon bamboo banana band
banjo bank barley barn barrel basic basil basin basket bat batch bath baton
battery bay beach beacon bead beam bean bear beard beat beauty beaver bed beech
beetle before begin behind being bell belt bench bend berry best better beyond
bicycle big bike bill binder birch bird birth biscuit bison bit black blade
blanket blaze blend bless blind blink block bloom blossom blue blur board boat
body boil bold bolt bond bone bonus book boost boot border boss both bottle
bottom bounce bound bow bowl box boy brace braid brain brake branch brass brave
bread break breeze brick bridge brief bright bring brisk broad bronze brook
broom brown brush bubble bucket buddy budget buffalo build bulb bulk bull bundle
bunny burn burst bus bush busy butter button buyer cabin cable cactus cage cake
calm camel camera camp canal candle candy cane canoe canvas canyon cap cape
captain car carbon card care cargo carpet carrot carry cart carve case cash
castle cat catch cattle cause cave cedar celery cell cement census center cereal
chain chair chalk champ chance change chapel charge charm chart chase cheap
check cheese chef cherry chess chest chief child chill chimney chip choice
choose chorus chrome chunk cider cinema circle citizen city civil claim clamp
clap clarity clay clean clear clerk clever click cliff climb clinic clip clock
close cloth cloud clover club clue coach coal coast coat cobra cocoa code coffee
coil coin cold collar colony color column comb combine come comet comfort comic
common compass concert cook cookie cool copper copy coral cord core corn corner
cost cotton couch count county couple course court cousin cover cow coyote crab
crack craft crane crash crate crawl crayon cream create credit creek crew cricket
crisp crop cross crowd crown crumb crush crystal cube cuff culture cup curl
current curtain curve cushion custom cycle daily dairy daisy dance danger dark
dart dash data date dawn day deal debate debris decade decide deck decor deep
deer defend degree delay delta demand denim dense dental depart depend deposit
depth derby desert design desk detail detect devote dial diamond diary dice
diesel diet dig dinner direct dirt disc dish disk ditch dive dizzy dock doctor
dodge dog dollar dolphin dome donate donkey door dose dot double dough dove down
dozen draft dragon drain drama draw dream dress drift drill drink drive drop
drum dry duck duet duke dune dusk dust duty eagle early earn earth ease east
easy echo edge edit effort egg eight either elbow elder elect element elephant
elite elk else email emerald emit empty enable enact end energy engine enjoy
enough enter entire entry envy epic equal equip era error escape essay estate
ethics evening event ever every exact exam excess exchange excite exit expand
expert extra eye fabric face fact fade fair faith fall false family famous fan
fancy farm fashion fast fault favor feast feather feature fee feed feel fence
fern ferry fever few fiber field fifth fig figure file fill film filter final
find fine finger finish fire firm first fish fist fit five fix flag flame flash
flat flavor flax fleet flesh flight flint float flock flood floor flour flow
flower fluid flute fly foam focus fog foil fold folk follow food foot force
forest forge fork form fort forum forward fossil found four fox frame free fresh
friend fringe frog front frost fruit fuel full fun fund fur future gadget gain
galaxy gallery game gap garage garden garlic gas gate gather gauge gaze gear gem
gene gentle giant gift ginger giraffe girl give glad glance glass glide globe
glory glove glow glue goal goat gold golf good goose grab grace grade grain
grand grant grape graph grass gravel gray great green grid grill grin grip
grocery ground group grove grow guard guess guest guide guitar gulf gym habit
hair half hall hammer hand happy harbor hard harvest hat hatch haven hawk hay
hazel head health heart heat heavy hedge height hello helmet help hen herb herd
here hero hidden high hill hint hip history hive hobby hockey hold hole holiday
hollow home honey honor hood hoof hook hope horizon horn horse hose host hot
hotel hour house hub huge human humble humor hunt hurdle hurry ice icon idea
ideal image impact inch index indoor infant inform inhale initial ink inner
input insect inside insight intact into invest invite iron island issue item
ivory ivy jacket jade jaguar jam jar jazz jeans jelly jewel job jog join joke
journal joy judge juice july jump june jungle junior just kayak keen keep kernel
key kick kidney kind king kiss kit kitchen kite kitten knee knife knight knock
knot know koala label labor lace ladder lady lake lamb lamp land lane language
lantern lap large laser last late laugh launch laundry lava law lawn layer lazy
leader leaf league lean learn lease leather leave ledge left leg legend lemon
lend length lens leopard lesson letter level liberty library license lid life
lift light like lily limb lime limit line link lion lip liquid list listen
little live lizard load loaf loan lobby local lock lodge log logic lonely long
look loop lord lose lot lotus loud love lower loyal luck lucky lumber lunar
lunch lung luxury lyric machine magic magnet maid mail main major make mammal
man mango manor mansion manual maple marble march margin marine market marsh
mask mass master match math matrix matter maze meadow meal mean measure meat
medal media medium meet melody melon melt member memory mention menu mercy merge
merit merry mesh message metal meter method middle midnight might mild mile milk
mill mind mine mint minute mirror mist mix mobile model modem modest moment
monday money monitor monkey month moon moral more morning most motion motor
mount mouse mouth move movie much mud muffin mule muscle museum mushroom music
must mutual myself mystery nail name napkin narrow nation native nature navy
near neat neck need needle neighbor nest net network never new news next nice
night nine noble node noise noodle noon normal north nose note notice novel now
number nurse nut oak oasis oats object ocean october odd offer office often oil
okay old olive omega once onion online only open opera option orange orbit
orchard order organ origin other otter ounce outer output outside oval oven over
owl owner oxygen oyster pace pack page paint pair palace palm panda panel panic
paper parade parcel parent park parrot part party pass past pasta patch path
patient patrol pattern pause pave peace peach peak peanut pear pearl pebble
pedal pen pencil penguin people pepper perfect perform period permit person pet
phone photo phrase piano pick picnic picture piece pier pigeon pile pilot pine
pink pint pioneer pipe pitch pizza place plain plan plane planet plank plant
plastic plate play please pledge plenty plot plug plum plus pocket poem poet
point polar pole police policy polish pond pony pool poppy popular porch port
portion post pot potato pottery pouch pound powder power praise prayer prefer
premium prepare present press pretty price pride prime print prior prism private
prize problem process produce profit program project promise proof proud prove
public pull pulse pump punch pupil puppy pure purple purse push puzzle pyramid
quality quarter queen query quest quick quiet quilt quit quiz quote rabbit
raccoon race rack radar radio raft rail rain raise rally ranch random range rank
rapid rare rate raven raw ray razor reach react read ready real reason rebel
recall recipe record recycle red reduce reef refer reform region regret regular
relax relief remain remind remote render renew rent repair repeat replace report
rescue reserve resist resort result retire return reveal review reward rhythm
ribbon rice rich ride ridge rifle right rigid ring rise risk ritual river road
roast robin robot rock rocket rod role roll roof room root rope rose rough round
route royal rubber ruby rug rule run rural rush rust sad safe sail salad salmon
salon salt sample sand satin sauce save scale scan scarf scene scent school
science scope score scout scrap screen script sea seal search season seat second
secret sector secure seed seek seem select sell send senior sense sentence
series serve session settle seven shade shadow shaft shake shallow shape share
shark sharp shed sheep sheet shelf shell shield shift shine ship shirt shock
shoe shoot shop shore short should shoulder show shrimp shrug shuffle side siege
sigh sight sign silent silk silly silver similar simple since sing single sink
sir sister sit site six size skate sketch ski skill skin skirt sky slab slam
sleep slice slide slight slim slogan slope slot slow small smart smile smoke
smooth snack snake snap sneak snow soap soccer social sock soda sofa soft solar
sold solid solve some song soon sort soul sound soup source south space spare
spark speak special speed spell spend sphere spice spider spike spin spirit
split spoke sponge spoon sport spot spray spread spring sprout spy square
squeeze squirrel stable stack staff stage stairs stamp stand star start state
station stay steady steak steam steel stem step stereo stick still sting stock
stone stool stop store storm story stove strap straw stream street stretch
strike string strong studio study stuff style subject submit subway sudden sugar
suggest suit summer sun sunset super supply support sure surf surge surprise
survey sushi swamp swan swap swarm sweat sweet swift swim swing switch sword
symbol syrup system table tackle tag tail tailor talent talk tall tank tape
target task taste tax tea teach team tear tech teeth tell temple tempo ten tenant
tennis tent term test text thank that theme then theory there these thick thin
thing think third thirty this thorn those three thrive throat throw thumb thunder
ticket tide tidy tiger tight tile timber time tiny tip tired tissue title toast
today toe together token tomato tone tongue tonight tool tooth top topic torch
total touch tough tour toward towel tower town toy trace track trade traffic
trail train tray treat tree trend trial tribe trick trip trophy trouble truck
true trust truth try tube tuna tunnel turkey turn turtle twelve twenty twice
twin twist two type unable uncle under uniform union unique unit unlock until
upon upper upset urban urge usage use useful usual valid valley value valve van
vanilla vapor variety vast vault velvet vendor venture venue verb verify verse
very vessel veteran victory video view village vintage violet violin virtual
virus visa visit visual vital vivid vocal voice volume vote voyage wagon waist
wait wake walk wall walnut want warm warn wash wasp waste watch water wave wax
way weak wealth weapon wear weather web wedge week weight weird welcome well
west whale wharf what wheat wheel when where which while whisper white whole why
wide width wife wild will willow win wind window wine wing wink winter wire wise
wish witness wolf woman wonder wood wool word work world worry worth wrap wrist
write yard yarn year yellow yield yoga young zebra zero zone zoo
"""

WORDS: List[str] = sorted({w for w in _RAW.split() if 2 <= len(w) <= 9})
WORD_SET = frozenset(WORDS)


def bits_per_word(words: Sequence[str] | None = None) -> float:
    n = len(words if words is not None else WORDS)
    return math.log2(n) if n > 1 else 0.0


def load_external(path: str) -> List[str]:
    """Load a larger word list from a local file (one word per line).

    Reads from your filesystem only. Lockbox never fetches word lists.
    """
    path = os.path.abspath(os.path.expanduser(path))
    words: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            token = line.strip().split()[-1] if line.strip() else ""
            token = "".join(ch for ch in token.lower() if ch.isalpha())
            if 2 <= len(token) <= 12:
                words.append(token)
    unique = sorted(set(words))
    if len(unique) < 16:
        raise ValueError("word list too small to be useful")
    return unique
